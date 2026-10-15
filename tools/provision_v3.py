#!/usr/bin/env python3
"""Provision Nanoleaf NL65 downlights into a Litewave control group via LTPDU v3.

Discovers lights locally over mDNS and writes:
  - Admin key (`sp/admin`)
  - PAN ID (`sp/pi`)
  - Radio channel (`sp/mc`)
  - Shared secret (`sp/ss`)
to configure and isolate them into their own cryptographic Litewave room group.

Session Methods:
  1. cloud_token (Default & Recommended):
     Retrieves existing auth tokens and home configuration (PAN ID, Admin Key, Channel)
     from Nanoleaf Cloud and authenticates via token. Reuses existing client slots
     and avoids consuming light pairing slots.
     Credentials can be passed via --cloud-email / --cloud-password or
     environment variables NANOLEAF_EMAIL / NANOLEAF_PASSWORD.

  2. new_pairing:
     Uses the 11-digit Matter setup code from the back of the light (e.g. 1640-700-5590).
     Requires the Home PAN ID (from Nanoleaf app/cloud, e.g. '3b71').

Usage Examples:
    # Recommended: Cloud Token method (prompts for email/password or uses env vars)
    python3 provision_v3.py --id 789 --secret 0x01

    # Cloud Token with explicit credentials:
    python3 provision_v3.py --id 789 --cloud-email user@example.com --cloud-password secret --secret 0x01

    # Multiple lights matching 3-digit IDs on the back:
    python3 provision_v3.py --id 789,1D9 --secret 0x01

    # New Pairing method (Matter setup code + PAN ID + Admin Key + Channel):
    python3 provision_v3.py --session-method new_pairing --id 789 --code 1640-700-5590 --pan-id 1234 --admin-key abcd --channel 26 --secret 0x01

    # Read-only check (inspect current shared secret without writing):
    python3 provision_v3.py --id 789 --read-only
"""

import argparse
import getpass
import os
import re
import sys
import time
from typing import Dict, List, Optional
from zeroconf import ServiceBrowser, Zeroconf

from ltpdu_v3 import LtpduV3Session
from nanoleaf_cloud import NanoleafCloudClient


def extract_light_id(service_name: str, props: dict) -> str:
    """Extract the 3 or 4 character hardware ID from the service name or props."""
    m = re.search(r"(?:DL|Downlight)\s+([A-Za-z0-9]+)", service_name, re.I)
    if m:
        return m.group(1).upper()
    prefix = service_name.split("-")[0].strip()
    words = prefix.split()
    if words:
        return words[-1].upper()
    return props.get("id", "?").upper()


def discover_lights(timeout=8.0) -> List[Dict]:
    """Discover LTPDU v3 lights via mDNS."""
    lights = []

    class Listener:
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name)
            if not info:
                return
            addrs = info.parsed_addresses()
            ipv6 = [a for a in addrs if ":" in a]
            props = {
                k.decode(): v.decode() if isinstance(v, bytes) else v
                for k, v in info.properties.items()
            }
            svc_name = name.replace("._ltpdu._udp.local.", "")
            light_id = extract_light_id(svc_name, props)
            eui_raw = props.get("eui64", props.get("eui", "")).replace(":", "").replace("-", "").lower()
            lights.append({
                "id": light_id,
                "name": svc_name,
                "host": ipv6[0] if ipv6 else addrs[0],
                "port": info.port,
                "model": props.get("md", "?"),
                "firmware": props.get("srcvers", "?"),
                "eui64": eui_raw,
                "raw_props": props,
            })

        def remove_service(self, *a):
            pass

        def update_service(self, *a):
            pass

    zc = Zeroconf()
    browser = ServiceBrowser(zc, "_ltpdu._udp.local.", Listener())
    time.sleep(timeout)
    zc.close()
    return lights


def parse_secret_hex(secret_str: str) -> bytes:
    """Parse and auto-pad hex shared secret to 54 bytes."""
    s = secret_str.strip().replace(" ", "").replace(":", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) > 108:
        raise ValueError(f"Shared secret too long ({len(s)} hex chars, max 108)")
    s = s.rjust(108, "0")
    return bytes.fromhex(s)


def derive_switch_acl_entry(switch_eui_or_id: str) -> bytes:
    """
    Derive the 4-byte switch identifier for Litewave ACL.
    The Nanoleaf app takes the 16-hex EUI-64: take(4) + takeLast(4), e.g.
    'e406bffffed47797' -> 'e406' + '7797' -> bytes.fromhex('e4067797').
    If an 8-hex string is provided directly, it is parsed directly.
    """
    clean = switch_eui_or_id.replace(":", "").replace("-", "").strip().lower()
    if clean.startswith("0x"):
        clean = clean[2:]
    if len(clean) == 16:
        entry_hex = clean[:4] + clean[-4:]
    elif len(clean) == 8:
        entry_hex = clean
    else:
        raise ValueError(f"Invalid switch EUI/ID: '{switch_eui_or_id}' (expected 16-hex EUI or 8-hex identifier)")
    return bytes.fromhex(entry_hex)


def build_acl_payload(switch_euis: List[str]) -> bytes:
    """
    Build TLV-encoded ACL payload matching Nanoleaf buildPutGroupCommand:
      Tag 0x01 (ControlList): 4 bytes per switch
      Tag 0x02 (MotionList):  4 bytes per switch
    """
    entries = [derive_switch_acl_entry(s) for s in switch_euis if s]
    if not entries:
        return b""
    ctrl_data = b"".join(entries)
    motion_data = b"".join(entries)
    return bytes([0x01, len(ctrl_data)]) + ctrl_data + bytes([0x02, len(motion_data)]) + motion_data


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--session-method",
        "-m",
        choices=["cloud_token", "new_pairing"],
        default="cloud_token",
        help="Authentication method: 'cloud_token' (recommended, reuses Nanoleaf app auth) or 'new_pairing' (uses Matter setup code)",
    )
    parser.add_argument(
        "--id",
        "--lights",
        dest="light_ids",
        help="3-character light ID(s) from back of light, comma-separated (e.g. '789' or '789,1D9')",
    )
    parser.add_argument(
        "--code",
        help="11-digit Matter pairing code (required for 'new_pairing' method, e.g. '1640-700-5590')",
    )
    parser.add_argument(
        "--pan-id",
        help="2-byte PAN ID hex string (e.g. '1234'). Auto-fetched from cloud in 'cloud_token' mode.",
    )
    parser.add_argument(
        "--channel",
        type=int,
        help="802.15.4 radio channel (11-26). Auto-fetched from cloud in 'cloud_token' mode.",
    )
    parser.add_argument(
        "--admin-key",
        help="2-byte Admin Key hex string. Auto-fetched from cloud in 'cloud_token' mode.",
    )
    parser.add_argument(
        "--cloud-email",
        default=os.environ.get("NANOLEAF_EMAIL") or os.environ.get("NANOLEAF_USERNAME"),
        help="Nanoleaf account email (or set NANOLEAF_EMAIL env var)",
    )
    parser.add_argument(
        "--cloud-password",
        default=os.environ.get("NANOLEAF_PASSWORD"),
        help="Nanoleaf account password (or set NANOLEAF_PASSWORD env var)",
    )
    parser.add_argument(
        "--cloud-token",
        default=os.environ.get("NANOLEAF_CLOUD_TOKEN"),
        help="Nanoleaf cloud bearer token (or set NANOLEAF_CLOUD_TOKEN env var)",
    )
    parser.add_argument(
        "--secret",
        help="Shared secret as hex string (e.g. '0x01' or '01', auto zero-padded to 54 bytes)",
    )
    parser.add_argument(
        "--switch-eui",
        "--switches",
        dest="switch_euis",
        help="Comma-separated Sense+ switch EUI-64 addresses (e.g. 'e406bffffed47797') to authorize in the light's ACL",
    )
    parser.add_argument(
        "--acl",
        help="Raw hex string for ACL payload (overrides auto-calculation from --switch-eui)",
    )
    parser.add_argument(
        "--host",
        help="Direct target IP or hostname (skips mDNS discovery)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=12566,
        help="Target port when using --host (default 12566)",
    )
    parser.add_argument(
        "--name",
        dest="service_name",
        help="mDNS service name of the light (e.g. 'Nanoleaf DL 655-76C8' or 'Nanoleaf DL 655')",
    )
    parser.add_argument(
        "--unpair-token",
        help="One-off action: authenticate with this existing auth_token and immediately send unpair to free its slot",
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        help="Only read current sp/ss without modifying anything",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="mDNS discovery scan time in seconds (default 8.0)",
    )
    args = parser.parse_args()

    # ── Step 1: Discover or Direct Target ──────────────────────────────────
    if args.host:
        light_id = args.light_ids.split(",")[0].strip().upper() if args.light_ids else "TARGET"
        svc_name = args.service_name or f"Nanoleaf DL {light_id}"
        targets = [{
            "id": light_id,
            "name": svc_name,
            "host": args.host,
            "port": args.port,
            "model": "NL65",
            "eui64": "",
            "raw_props": {},
        }]
        print(f"Using direct target light: {svc_name} at {args.host}:{args.port}")
    else:
        print(f"Discovering Nanoleaf lights via mDNS ({args.timeout:.0f}s)...")
        all_discovered = discover_lights(timeout=args.timeout)
        if not all_discovered:
            print("No Nanoleaf lights found on the network via mDNS.")
            print("Make sure the lights are powered on and on the same Thread/WiFi network.")
            return

        print(f"\nDiscovered {len(all_discovered)} light(s) on local network:")
        print(f"  {'#':<3} {'ID':<6} {'Service Name':<28} {'Model':<6} {'EUI64':<18} {'IP Host'}")
        print("  " + "─" * 78)
        for i, l in enumerate(all_discovered):
            eui_display = l["eui64"] if l["eui64"] else "(none)"
            print(f"  [{i}] {l['id']:<6} {l['name']:<28} {l['model']:<6} {eui_display:<18} {l['host']}")
        print()

        # ── Step 2: Filter Target Lights by 3-character ID ──────────────────────
        if args.light_ids:
            wanted_ids = [x.strip().upper() for x in args.light_ids.split(",") if x.strip()]
            targets = [l for l in all_discovered if l["id"] in wanted_ids]
            if not targets:
                print(f"None of the discovered lights match ID(s): {', '.join(wanted_ids)}")
                return
            print(f"Selected {len(targets)} light(s) matching ID filter: {', '.join(wanted_ids)}")
        else:
            while True:
                try:
                    choice = input("Enter 3-character light ID(s) from back of light (e.g. '789' or '789,1D9', or 'all'): ").strip()
                    if not choice:
                        print("No selection made. Aborting.")
                        return
                    if choice.lower() == "all":
                        confirm = input("⚠️  WARNING: You chose ALL lights. Are you sure you want to write to all lights? [y/N]: ").strip().lower()
                        if confirm in ("y", "yes"):
                            targets = all_discovered
                            break
                        else:
                            continue

                    selected_tokens = [x.strip().upper() for x in choice.split(",") if x.strip()]
                    targets = []
                    for tok in selected_tokens:
                        if tok.isdigit() and 0 <= int(tok) < len(all_discovered):
                            targets.append(all_discovered[int(tok)])
                        else:
                            matched = [l for l in all_discovered if l["id"] == tok]
                            targets.extend(matched)

                    if targets:
                        break
                    print("No matching lights found for that selection. Try again.")
                except (KeyboardInterrupt, EOFError):
                    print("\nAborted.")
                    return

    # ── Handle Direct Unpair Request ─────────────────────────────────────────
    if args.unpair_token:
        tok_clean = args.unpair_token.strip().replace(" ", "").replace("0x", "")
        print(f"\n{'━'*60}")
        print(f"  Unpairing {len(targets)} Light(s)")
        print(f"{'━'*60}")
        for idx, light in enumerate(targets):
            print(f"\n[{idx + 1}/{len(targets)}] Light ID: {light['id']} ({light['name']})")
            print(f"  Host: {light['host']}:{light['port']}")
            session = LtpduV3Session(light["host"], light["port"])
            try:
                print(f"  Authenticating with auth token ({tok_clean[:12]}...)...")
                session.authenticate(light["name"], bytes.fromhex(tok_clean))
                session.unpair()
                print("  ✓ SUCCESS: Unpaired! Client slot freed on light.")
            except Exception as e:
                print(f"  ❌ ERROR: {e}")
                session.close()
        print(f"\n{'━'*60}")
        print("  Complete!")
        print(f"{'━'*60}")
        return

    # ── Step 3: Handle Session Method Credentials & Group Config ────────────
    cloud_device_map = {}
    pan_id_hex = args.pan_id
    admin_key_hex = args.admin_key
    channel_val = args.channel
    acl_payload = None

    if args.acl:
        acl_payload = bytes.fromhex(args.acl.replace("0x", "").strip())
        print(f"Using manual ACL payload: {acl_payload.hex()}")
    elif args.switch_euis:
        switch_list = [s.strip() for s in args.switch_euis.split(",") if s.strip()]
        acl_payload = build_acl_payload(switch_list)
        print(f"Configured ACL for {len(switch_list)} switch(es) from CLI flag: {acl_payload.hex()}")

    if args.session_method == "cloud_token":
        print("\n--- Nanoleaf Cloud Authentication ---")
        email = args.cloud_email
        password = args.cloud_password
        token = args.cloud_token

        if not token and (not email or not password):
            if not email:
                try:
                    email = input("Nanoleaf Account Email: ").strip()
                except (KeyboardInterrupt, EOFError):
                    print("\nAborted.")
                    return
            if not password:
                try:
                    password = getpass.getpass("Nanoleaf Account Password: ").strip()
                except (KeyboardInterrupt, EOFError):
                    print("\nAborted.")
                    return

        try:
            cloud_client = NanoleafCloudClient(username=email, password=password, access_token=token)
            if not token:
                print("Logging in to Nanoleaf Cloud...")
                cloud_client.login()
            print("Fetching device auth tokens and home configuration...")
            cloud_devices = cloud_client.get_devices()
            home_cfg = cloud_client.get_home_config()

            if not pan_id_hex:
                pan_id_hex = home_cfg.get("pan_id")
            if not admin_key_hex:
                admin_key_hex = home_cfg.get("admin_key")
            if channel_val is None:
                channel_val = home_cfg.get("channel")

            if not pan_id_hex:
                raise ValueError("Could not find Home PAN ID in Nanoleaf Cloud. Pass via --pan-id.")
            if not admin_key_hex:
                raise ValueError("Could not find Home Admin Key in Nanoleaf Cloud. Pass via --admin-key.")
            if channel_val is None:
                raise ValueError("Could not find Home Preferred Channel in Nanoleaf Cloud. Pass via --channel.")

            print(f"Retrieved {len(cloud_devices)} device(s). Home config: PAN=0x{pan_id_hex} Channel={channel_val} AdminKey=0x{admin_key_hex}")

            for cd in cloud_devices:
                if cd.get("eui64"):
                    cloud_device_map[cd["eui64"]] = cd
                name_id = extract_light_id(cd.get("name", ""), {})
                if name_id and name_id != "?":
                    cloud_device_map[name_id] = cd

            # Auto-detect switches for ACL if not manually specified
            if not acl_payload:
                cloud_switches = [
                    d for d in cloud_devices
                    if d.get("model") == "NL44" and not d.get("deleted") and d.get("eui64")
                ]
                if cloud_switches:
                    if len(cloud_switches) == 1:
                        found_euis = [cloud_switches[0]["eui64"]]
                        print(f"\nAuto-selected only Sense+ switch in home: {cloud_switches[0]['name']} (EUI: {found_euis[0]})")
                    else:
                        print(f"\nMultiple ({len(cloud_switches)}) Sense+ switch(es) found in Nanoleaf Cloud:")
                        for idx, s in enumerate(cloud_switches, 1):
                            print(f"  [{idx}] {s['name']:28s} EUI: {s['eui64']}")
                        while True:
                            try:
                                choice = input(f"Select which switch to authorize for this group [1-{len(cloud_switches)}, or 'all']: ").strip()
                                if choice.lower() == "all":
                                    found_euis = [s["eui64"] for s in cloud_switches]
                                    break
                                elif choice.isdigit() and 1 <= int(choice) <= len(cloud_switches):
                                    found_euis = [cloud_switches[int(choice) - 1]["eui64"]]
                                    break
                            except (KeyboardInterrupt, EOFError):
                                print("\nAborted.")
                                return

                    if found_euis:
                        acl_payload = build_acl_payload(found_euis)
                        print(f"  -> Generated ACL for {len(found_euis)} switch(es): {acl_payload.hex()}")

        except Exception as e:
            print(f"❌ Failed to retrieve tokens from Nanoleaf Cloud: {e}")
            print("\nTip: You can switch to '--session-method new_pairing' and provide the Matter setup code.")
            return

    elif args.session_method == "new_pairing":
        if not args.code:
            try:
                args.code = input("Enter 11-digit Matter pairing code (e.g. '1640-700-5590'): ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nAborted.")
                return

        if not args.read_only:
            if not pan_id_hex:
                try:
                    pan_id_hex = input("Enter Nanoleaf Home PAN ID (hex, e.g. from Nanoleaf app/cloud): ").strip()
                except (KeyboardInterrupt, EOFError):
                    print("\nAborted.")
                    return
            if not admin_key_hex:
                try:
                    admin_key_hex = input("Enter Nanoleaf Home Admin Key (hex): ").strip()
                except (KeyboardInterrupt, EOFError):
                    print("\nAborted.")
                    return
            if channel_val is None:
                try:
                    ch_in = input("Enter 802.15.4 channel (11-26, default 26): ").strip()
                    channel_val = int(ch_in) if ch_in else 26
                except (KeyboardInterrupt, EOFError):
                    print("\nAborted.")
                    return

    # Normalize group radio config bytes
    pan_id_clean = pan_id_hex.replace("0x", "").rjust(4, "0") if pan_id_hex else ""
    admin_key_clean = admin_key_hex.replace("0x", "").rjust(4, "0") if admin_key_hex else ""
    pan_bytes = bytes.fromhex(pan_id_clean) if pan_id_clean else b""
    admin_bytes = bytes.fromhex(admin_key_clean) if admin_key_clean else b""
    channel_bytes = bytes([channel_val]) if channel_val is not None else b""

    # ── Step 4: Resolve Shared Secret ───────────────────────────────────────
    if args.secret:
        try:
            secret = parse_secret_hex(args.secret)
        except ValueError as e:
            print(f"Error in shared secret: {e}")
            return
    elif not args.read_only:
        secret = os.urandom(54)
        print(f"\nGenerated random shared secret: {secret.hex()}")
    else:
        secret = None

    # ── Step 5: Process Target Lights ───────────────────────────────────────
    print(f"\n{'━'*60}")
    action_label = "Inspecting" if args.read_only else "Provisioning"
    print(f"  {action_label} {len(targets)} Light(s) via [{args.session_method}]")
    print(f"{'━'*60}")

    codes = [c.strip() for c in args.code.split(",")] if args.code else []

    for idx, light in enumerate(targets):
        print(f"\n[{idx + 1}/{len(targets)}] Light ID: {light['id']} ({light['name']})")
        print(f"  Host: {light['host']}:{light['port']}")
        if light.get("eui64"):
            print(f"  EUI64: {light['eui64']}")

        session = LtpduV3Session(light["host"], light["port"])
        try:
            if args.session_method == "cloud_token":
                cloud_dev = cloud_device_map.get(light["eui64"]) or cloud_device_map.get(light["id"])
                if not cloud_dev or not cloud_dev.get("auth_token"):
                    print(f"  ❌ No auth token found in Nanoleaf Cloud for EUI {light['eui64']} (ID: {light['id']})")
                    print("     Make sure this light is added to your Nanoleaf app/account.")
                    continue

                auth_tok_hex = cloud_dev["auth_token"]
                print(f"  Using Cloud auth token ({auth_tok_hex[:12]}...) for '{cloud_dev['name']}'")
                session.authenticate(light["name"], bytes.fromhex(auth_tok_hex))
                print("  ✓ Authenticated successfully via Cloud Token!")

            else:
                code = codes[idx] if idx < len(codes) else (codes[0] if codes else args.code)
                print(f"  Pairing via setup code: {code}...")
                auth_token = session.pair(light["name"], code)
                if auth_token:
                    print(f"  ✓ Paired successfully! Auth Token: {auth_token.hex()[:16]}...")

            # Read current shared secret
            status, cur_val = session.get("sp/ss")
            if status == 0 and cur_val:
                cur_short = f"0x{cur_val.hex().lstrip('0') or '0'}"
                print(f"  Current sp/ss ({len(cur_val)}B): {cur_short} ({cur_val.hex()[:16]}...)")
            else:
                print(f"  Current sp/ss: none/empty (status={status})")

            # Read current ACL
            st_acl, cur_acl = session.get("lb/0/sp/llc/acl")
            if st_acl != 0:
                st_acl, cur_acl = session.get("sp/llc/acl")
            if st_acl == 0 and cur_acl:
                print(f"  Current ACL: {cur_acl.hex()}")
            else:
                print(f"  Current ACL: (empty / not set)")

            # Write group parameters if not read-only
            if not args.read_only:
                # 1. Admin Key
                print(f"  Setting Admin Key (0x{admin_key_clean})...")
                session.post("sp/admin", admin_bytes)

                # 2. PAN ID
                print(f"  Setting PAN ID (0x{pan_id_clean})...")
                session.post("sp/pi", pan_bytes)

                # 3. Radio Channel
                print(f"  Setting Channel ({channel_val})...")
                session.post("sp/mc", channel_bytes)

                # 4. Shared Secret
                if secret:
                    short_hex = f"0x{secret.hex().lstrip('0') or '0'}"
                    print(f"  Writing Shared Secret ({short_hex})...")
                    status, rval = session.post("sp/ss", secret)
                    if status == 0 or status == -1:
                        print("  ✓ SUCCESS: Light group parameters and shared secret written!")
                    else:
                        print(f"  ❌ Write failed (status code: {status})")

                # 5. Access Control List (ACL)
                if acl_payload:
                    print(f"  Writing Switch ACL ({len(acl_payload)}B: {acl_payload.hex()})...")
                    status, _ = session.put("lb/0/sp/llc/acl", acl_payload)
                    if status != 0:
                        status, _ = session.put("sp/llc/acl", acl_payload)
                    if status == 0 or status == -1:
                        print("  ✓ SUCCESS: Switch ACL written and authorized!")
                    else:
                        print(f"  ❌ ACL write failed (status code: {status})")

                    # Verify readback
                    st_acl2, cur_acl2 = session.get("lb/0/sp/llc/acl")
                    if st_acl2 != 0:
                        st_acl2, cur_acl2 = session.get("sp/llc/acl")
                    if st_acl2 == 0 and cur_acl2:
                        print(f"  -> Verified ACL on device: {cur_acl2.hex()}")

            if args.session_method == "new_pairing":
                print("  Cleaning up temporary pairing slot (unpair)...")
                session.unpair()
            else:
                session.disconnect()

        except Exception as e:
            print(f"  ❌ ERROR: {e}")
            session.close()

    print(f"\n{'━'*60}")
    print("  Complete!")
    print(f"{'━'*60}")


if __name__ == "__main__":
    main()
