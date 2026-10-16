#!/usr/bin/env python3
"""
Generate a catalog of pre-captured Litewave tokens for 100 deterministic
shared secrets.

Each shared secret is 54 bytes: 53 zero bytes followed by the index byte
(0x00 through 0x63). For each secret, the tool:
  1. Writes the secret to the Sense+ switch via BLE
  2. Prompts the user to press ON, OFF, DIM+, DIM- buttons
  3. Captures each token via the ESP32-C6 sniffer
  4. Appends the entry to token_catalog.yaml

The catalog lets ESPHome users skip manual capture entirely — just pick an
entry, provision their lights with that shared secret, and use the
pre-cataloged tokens.

Usage:
    python3 generate_catalog.py \
        --switch-name "Nanoleaf Wireless SW 1D9" \
        --switch-code "0242-362-0007" \
        [--port /dev/cu.usbmodem1101] \
        [--start 0] \
        [--count 100] \
        [--skip-dim] \
        [--output token_catalog.yaml]

Requirements:
    pip install bleak cryptography pyserial pyyaml
"""

import argparse
import asyncio
import os
import sys
import time

import serial
import yaml

# Import from sibling module
sys.path.insert(0, os.path.dirname(__file__))
from capture_and_provision import (
    BUTTONS,
    capture_command,
    select_serial_port,
    verify_sniffer_firmware,
    write_shared_secret_ble,
)


class HexInt(int):
    """Integer that formats as hexadecimal (e.g. 0xC8) in YAML."""
    pass


def _hexint_representer(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:int', f"0x{data:02X}")


yaml.add_representer(HexInt, _hexint_representer)
yaml.SafeDumper.add_representer(HexInt, _hexint_representer)


def format_shared_secret(secret_bytes: bytes) -> str:
    """Format shared secret in short hex format (e.g. '0x01') for readability."""
    hex_str = secret_bytes.hex().lstrip("0")
    if not hex_str:
        return "0x00"
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str
    return f"0x{hex_str}"


def secret_for_index(i):
    """Generate a deterministic 54-byte shared secret for catalog index i."""
    if i < 256:
        return bytes(53) + bytes([i])
    else:
        # For indices >= 256, use two trailing bytes
        return bytes(52) + bytes([i >> 8, i & 0xFF])


def load_existing_catalog(path):
    """Load existing catalog entries so we can resume."""
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    if data and "entries" in data:
        return data["entries"]
    return []


def parse_secret_int(secret_val) -> int:
    """Extract numeric value of a shared secret for sorting."""
    if isinstance(secret_val, int):
        return secret_val
    s = str(secret_val).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16) if s else 0


def save_catalog(path, entries):
    """Write the full catalog to YAML sorted by numeric shared_secret value."""
    # Deduplicate entries by shared_secret and sort numerically
    seen = {}
    for e in entries:
        sec = e.get("shared_secret")
        if sec:
            val = parse_secret_int(sec)
            seen[val] = e

    sorted_entries = [seen[k] for k in sorted(seen.keys())]

    header = (
        "# Pre-generated Litewave token catalog\n"
        "# Each entry maps a deterministic shared_secret and switch_eui to captured tokens.\n"
        "# Shared secrets are 54 bytes (represented in short form, e.g. 0x01).\n"
        "# Users can pick any entry and skip the manual capture process.\n"
        "#\n"
        "# To use an entry:\n"
        "#   1. Note the switch_eui, shared_secret, and token values\n"
        "#   2. Provision your lights with that shared_secret and switch_eui\n"
        "#   3. Use the tokens in your ESPHome YAML config\n"
        "\n"
    )
    with open(path, "w") as f:
        f.write(header)
        yaml.dump({"entries": sorted_entries}, f, default_flow_style=False, sort_keys=False)


def main():
    parser = argparse.ArgumentParser(
        description="Generate Litewave token catalog for pre-defined shared secrets"
    )
    parser.add_argument(
        "--switch-name",
        required=True,
        help="BLE device name of the Sense+ switch",
    )
    parser.add_argument(
        "--switch-eui",
        help="16-hex character EUI-64 of the Sense+ switch (e.g. 'e406bffffed47797')",
    )
    parser.add_argument(
        "--switch-code",
        help="Setup code on the back of the switch (e.g. '0242-362-0007')",
    )
    parser.add_argument(
        "--switch-token",
        help="16-hex Nanoleaf Cloud auth token for the switch (alternative to --switch-code)",
    )
    parser.add_argument(
        "--pan-id",
        help="2-byte PAN ID hex string (e.g. from Nanoleaf cloud/app)",
    )
    parser.add_argument(
        "--admin-key",
        help="2-byte Admin Key hex string (e.g. from Nanoleaf cloud/app)",
    )
    parser.add_argument(
        "--channel",
        type=int,
        help="802.15.4 radio channel (11-26)",
    )
    parser.add_argument(
        "--cloud-email",
        default=os.environ.get("NANOLEAF_EMAIL") or os.environ.get("NANOLEAF_USERNAME"),
        help="Nanoleaf account email (to auto-fetch PAN ID, Admin Key, Channel, and Switch EUI)",
    )
    parser.add_argument(
        "--cloud-password",
        default=os.environ.get("NANOLEAF_PASSWORD"),
        help="Nanoleaf account password",
    )
    parser.add_argument("--port", help="Sniffer serial port (auto-detected)")
    parser.add_argument(
        "--baud", type=int, default=115200, help="Baud rate (default 115200)"
    )
    parser.add_argument(
        "--start", type=int, default=0, help="Starting index (default 0)"
    )
    parser.add_argument(
        "--count", type=int, default=100, help="Number of entries (default 100)"
    )
    parser.add_argument(
        "--skip-dim",
        action="store_true",
        help="Only capture ON and OFF (skip dim buttons)",
    )
    parser.add_argument(
        "--output",
        default="token_catalog.yaml",
        help="Output file (default: token_catalog.yaml)",
    )
    parser.add_argument(
        "--auto-flash",
        action="store_true",
        help="Automatically flash sniffer firmware if not already running",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Show raw sniffer frames"
    )
    args = parser.parse_args()

    # Load existing entries for resume support
    existing = load_existing_catalog(args.output)
    existing_secrets = set()
    for e in existing:
        if "shared_secret" in e:
            s_val = str(e["shared_secret"]).strip().lower()
            if s_val.startswith("0x"):
                s_val = s_val[2:]
            s_val = s_val.rjust(108, "0")
            existing_secrets.add(s_val)
    print(
        f"Loaded {len(existing)} existing entries from {args.output}"
        if existing
        else f"Starting fresh catalog: {args.output}"
    )

    # Open sniffer port
    port = select_serial_port(args.port)
    if not port:
        print("No serial port found. Connect the ESP32-C6 sniffer.")
        sys.exit(1)

    try:
        ser = serial.Serial(port, args.baud, timeout=0.1)
    except serial.SerialException as e:
        print(f"Could not open {port}: {e}")
        sys.exit(1)

    time.sleep(0.5)
    ser.reset_input_buffer()

    ok, ser = verify_sniffer_firmware(ser, port, auto_flash=args.auto_flash)
    if not ok:
        if ser:
            ser.close()
        sys.exit(1)

    print(f"Sniffer: {port}")

    # Resolve parameters from cloud if needed
    pan_id_hex = args.pan_id
    admin_key_hex = args.admin_key
    channel_val = args.channel
    switch_eui = args.switch_eui

    # If explicitly passed via arguments, prefer user-specified switch_code / switch_token
    auth_val = args.switch_token if args.switch_token else args.switch_code

    if args.cloud_email and args.cloud_password:
        try:
            from nanoleaf_cloud import NanoleafCloudClient
            cloud_client = NanoleafCloudClient(username=args.cloud_email, password=args.cloud_password)
            home_cfg = cloud_client.get_home_config()
            if not pan_id_hex:
                pan_id_hex = home_cfg.get("pan_id")
            if not admin_key_hex:
                admin_key_hex = home_cfg.get("admin_key")
            if channel_val is None:
                channel_val = home_cfg.get("channel")

            if not switch_eui or not auth_val:
                cloud_devs = cloud_client.get_devices()
                for cd in cloud_devs:
                    if (cd.get("name") == args.switch_name) or (not switch_eui and cd.get("model") == "NL44" and not cd.get("deleted")):
                        if not switch_eui and cd.get("eui64"):
                            switch_eui = cd["eui64"]
                        if not auth_val and cd.get("auth_token"):
                            auth_val = cd["auth_token"]
                        if cd.get("name") == args.switch_name:
                            break
        except Exception as e:
            if args.debug:
                print(f"  (Cloud lookup error: {e})")

    if not pan_id_hex:
        pan_id_hex = "3411"
    if not admin_key_hex:
        admin_key_hex = "0000"
    if channel_val is None:
        channel_val = 26
    if not auth_val:
        print("ERROR: Either --switch-code or --switch-token is required.")
        sys.exit(1)

    print(f"Switch: {args.switch_name} (EUI: {switch_eui or 'unknown'})")
    print(f"Radio:  PAN=0x{pan_id_hex} Channel={channel_val} AdminKey=0x{admin_key_hex}")

    buttons = BUTTONS if not args.skip_dim else BUTTONS[:2]
    end_index = args.start + args.count
    first_write = True

    for idx in range(args.start, end_index):
        secret = secret_for_index(idx)
        secret_hex = secret.hex().lower()

        if secret_hex in existing_secrets:
            print(f"\n[{idx}/{end_index - 1}] Shared secret {format_shared_secret(secret)} already in catalog, skipping")
            continue

        print(f"\n{'='*60}")
        print(f"  [{idx}/{end_index - 1}] Capturing index {idx}")
        print(f"  Secret: {format_shared_secret(secret)} ({secret.hex()})")
        print(f"{'='*60}")

        # Write secret to switch via BLE (only configure radio params on first write)
        print(
            "\n  Press any button on the switch to wake BLE, then wait..."
        )
        ok = asyncio.run(
            write_shared_secret_ble(
                args.switch_name,
                auth_val,
                secret,
                pan_id_hex,
                admin_key_hex,
                channel_val,
                write_radio_params=first_write,
            )
        )
        if not ok:
            print("  BLE write FAILED. Retrying after a pause...")
            time.sleep(5)
            ok = asyncio.run(
                write_shared_secret_ble(
                    args.switch_name,
                    auth_val,
                    secret,
                    pan_id_hex,
                    admin_key_hex,
                    channel_val,
                    write_radio_params=first_write,
                )
            )
            if not ok:
                print("  BLE write failed twice. Saving progress and exiting.")
                save_catalog(args.output, existing)
                ser.close()
                sys.exit(1)

        first_write = False

        # Capture each button
        target_pan_int = int(pan_id_hex, 16) if pan_id_hex else None
        entry = {
            "index": idx,
            "shared_secret": format_shared_secret(secret),
        }
        if switch_eui:
            entry["switch_eui"] = switch_eui.lower()
        all_captured = True

        for key, label in buttons:
            result = capture_command(ser, label, target_pan=target_pan_int, timeout=45, debug=args.debug)
            if result is None:
                if key in ("dim_plus", "dim_minus"):
                    print(f"  Skipping {label} (not captured)")
                    continue
                else:
                    print(f"  FAILED to capture {label}. Retry this index.")
                    all_captured = False
                    break

            seq, tok = result
            entry[f"{key}_sequence"] = HexInt(seq)
            entry[f"{key}_token"] = tok

        if not all_captured:
            print("  Incomplete capture. Try this index again with --start")
            continue

        # Clean ordering for keys: shared_secret, switch_eui, sequences & tokens
        ordered_entry = {
            "shared_secret": entry.get("shared_secret"),
        }
        if "switch_eui" in entry:
            ordered_entry["switch_eui"] = entry["switch_eui"]
        for k, _ in buttons:
            if f"{k}_sequence" in entry:
                ordered_entry[f"{k}_sequence"] = entry[f"{k}_sequence"]
            if f"{k}_token" in entry:
                ordered_entry[f"{k}_token"] = entry[f"{k}_token"]

        existing.append(ordered_entry)
        existing_secrets.add(secret_hex)

        # Save after each successful capture (crash-safe)
        save_catalog(args.output, existing)
        print(
            f"\n  Saved index {idx} "
            f"({len(existing)}/{args.count} complete)"
        )

    ser.close()

    print(f"\n{'━'*60}")
    print(f"  Catalog complete: {len(existing)} entries in {args.output}")
    print(f"{'━'*60}")


if __name__ == "__main__":
    main()
