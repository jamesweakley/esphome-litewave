#!/usr/bin/env python3
"""
Convert a JSON capture to PCAP with IEEE 802.15.4 TAP headers for Wireshark.
Use Wireshark's built-in Thread decryption for proper analysis.

Usage:
    python json_to_pcap.py captures/pairing.json captures/pairing.pcap

Then in Wireshark:
    Edit > Preferences > Protocols > Thread > Thread Network Key: 13c1e14725ad7bc0591748b330e296bf
    (or add via Edit > Preferences > Protocols > IEEE 802.15.4 > Decryption Keys)
"""

import json
import struct
import sys
import time


PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_IEEE802154_TAP = 283

TAP_TLV_FCS_TYPE = 0
TAP_TLV_RSS = 1
TAP_TLV_CHANNEL = 3
TAP_TLV_LQI = 10


def build_tap_header(channel, rssi, lqi):
    tlvs = b""
    # FCS type 0 = no FCS present (we strip the 2-byte FCS from frames)
    tlvs += struct.pack("<HHB", TAP_TLV_FCS_TYPE, 1, 0)
    tlvs += b"\x00" * 3
    tlvs += struct.pack("<HHf", TAP_TLV_RSS, 4, float(rssi))
    freq = 2405 + (channel - 11) * 5
    tlvs += struct.pack("<HH HHH", TAP_TLV_CHANNEL, 6, 0, channel, freq)
    tlvs += b"\x00" * 2
    tlvs += struct.pack("<HHI", TAP_TLV_LQI, 4, lqi)
    header_len = 4 + len(tlvs)
    return struct.pack("<HH", 0, header_len) + tlvs


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.json> <output.pcap>")
        sys.exit(1)

    frames = [json.loads(l) for l in open(sys.argv[1])]

    with open(sys.argv[2], "wb") as f:
        # Global header
        f.write(struct.pack("<IHHIIII",
            PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
            0, 0, 65535, PCAP_LINKTYPE_IEEE802154_TAP
        ))

        for frame in frames:
            raw = bytes.fromhex(frame["frame_hex"])
            ch = frame["channel"]
            rssi = frame["rssi"]
            lqi = frame["lqi"]
            ts = frame["time"]

            # Strip last 2 bytes (FCS) - ESP32-C6 radio often corrupts them
            if len(raw) > 2:
                raw = raw[:-2]
            tap = build_tap_header(ch, rssi, lqi)
            packet = tap + raw

            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(packet), len(packet)))
            f.write(packet)

    print(f"Wrote {len(frames)} frames to {sys.argv[2]}")
    print()
    print("To decrypt in Wireshark:")
    print("  1. Open the PCAP file")
    print("  2. Edit > Preferences > Protocols > Thread")
    print("  3. Set Thread Network Key (or add under IEEE 802.15.4 Decryption Keys)")
    print("  4. Apply, and Thread payloads should be visible")


if __name__ == "__main__":
    main()
