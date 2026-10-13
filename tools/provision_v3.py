#!/usr/bin/env python3
"""Provision a Nanoleaf NL65 downlight into a Litewave control group via LTPDU v3.

Usage:
    python3 provision_v3.py --code 1640-700-5590

Discovers lights via mDNS, authenticates via SRP-6a PairingCode,
reads/writes the sp/ss shared secret to register the light in a control group.
"""
import argparse
import socket
import time
import os
from zeroconf import Zeroconf, ServiceBrowser

from ltpdu_v3 import LtpduV3Session


def discover_lights(timeout=8.0):
    """Discover LTPDU v3 lights via mDNS."""
    lights = []

    class Listener:
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name)
            if not info:
                return
            addrs = info.parsed_addresses()
            ipv6 = [a for a in addrs if ":" in a]
            props = {k.decode(): v.decode() if isinstance(v, bytes) else v
                     for k, v in info.properties.items()}
            svc_name = name.replace("._ltpdu._udp.local.", "")
            lights.append({
                "name": svc_name,
                "host": ipv6[0] if ipv6 else addrs[0],
                "port": info.port,
                "model": props.get("md", "?"),
                "firmware": props.get("srcvers", "?"),
                "eui64": props.get("eui64", "?"),
                "id": props.get("id", "?"),
            })

        def remove_service(self, *a): pass
        def update_service(self, *a): pass

    zc = Zeroconf()
    browser = ServiceBrowser(zc, "_ltpdu._udp.local.", Listener())
    time.sleep(timeout)
    zc.close()
    return lights


def main():
    parser = argparse.ArgumentParser(description="Provision NL65 lights via LTPDU v3 SRP")
    parser.add_argument("--code", required=True, help="11-digit Matter pairing code (e.g. 1640-700-5590)")
    parser.add_argument("--host", help="IPv6 address (skip mDNS discovery)")
    parser.add_argument("--name", help="Service name (required with --host)")
    parser.add_argument("--secret", help="54-byte hex shared secret to write")
    parser.add_argument("--read-only", action="store_true", help="Only read current sp/ss, don't write")
    args = parser.parse_args()

    # Discover or use provided host
    if args.host:
        if not args.name:
            parser.error("--name is required when using --host")
        targets = [{"name": args.name, "host": args.host, "port": 12566,
                     "model": "?", "firmware": "?", "eui64": "?", "id": "?"}]
    else:
        print("Discovering lights...")
        targets = discover_lights()
        if not targets:
            print("No lights found.")
            return
        print(f"Found {len(targets)} light(s):")
        for i, light in enumerate(targets):
            print(f"  [{i}] {light['name']} ({light['model']} fw {light['firmware']}) "
                  f"@ {light['host']}:{light['port']}")

    # Generate a shared secret if not provided
    if args.secret:
        s = args.secret.strip().replace(" ", "").replace(":", "")
        if s.lower().startswith("0x"):
            s = s[2:]
        if len(s) > 108:
            print(f"Error: shared secret too long ({len(s)} hex chars, max 108)")
            return
        s = s.rjust(108, "0")
        try:
            secret = bytes.fromhex(s)
        except ValueError as e:
            print(f"Error: invalid hexadecimal in shared secret: {e}")
            return
    elif not args.read_only:
        secret = os.urandom(54)
        print(f"\nGenerated shared secret: {secret.hex()}")
    else:
        secret = None

    # Process each light
    for light in targets:
        print(f"\n{'='*60}")
        print(f"Light: {light['name']}")
        print(f"  Host: {light['host']}:{light['port']}")

        session = LtpduV3Session(light["host"], light["port"])
        try:
            # Step 1-3: SRP authenticate and get auth token
            auth_token = session.pair(light["name"], args.code)
            if auth_token:
                print(f"  Auth token: {auth_token.hex()}")

            # Read current shared secret
            print(f"\n  Reading sp/ss...")
            status, value = session.get("sp/ss")
            if status == 0 and value:
                print(f"  Current sp/ss ({len(value)}B): {value.hex()}")
            else:
                print(f"  Current sp/ss: empty (status={status})")

            # Write new shared secret
            if secret and not args.read_only:
                print(f"\n  Writing sp/ss ({len(secret)}B)...")
                status, rval = session.post("sp/ss", secret)
                print(f"  Write status: {status}")

                # Verify readback
                print(f"  Verifying readback...")
                status, value = session.get("sp/ss")
                if value == secret:
                    print(f"  VERIFIED: sp/ss matches!")
                else:
                    print(f"  WARNING: readback mismatch!")
                    print(f"    Expected: {secret.hex()}")
                    print(f"    Got:      {value.hex() if value else 'empty'}")

            session.disconnect()
            print(f"  Done.")

        except Exception as e:
            print(f"  ERROR: {e}")
            session.close()


if __name__ == "__main__":
    main()
