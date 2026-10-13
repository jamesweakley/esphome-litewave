#!/usr/bin/env python3
"""
Litewave 802.15.4 Sniffer — Host Capture Tool

Reads framed 802.15.4 packets from the ESP32-C6 sniffer over USB serial,
writes PCAP (IEEE 802.15.4 TAP link type) and prints live analysis.

Usage:
    python capture.py [--port /dev/cu.usbmodem1101] [--pcap capture.pcap] [--json frames.json]

    Pipe to Wireshark:
        python capture.py --pcap - | wireshark -k -i -
"""

import argparse
import json
import struct
import sys
import time
from collections import defaultdict
from datetime import datetime

import serial

SYNC_BYTE = 0xAA

# PCAP constants
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_IEEE802154_TAP = 283  # IEEE 802.15.4 TAP

# IEEE 802.15.4 TAP TLV types
TAP_TLV_FCS_TYPE = 0
TAP_TLV_RSS = 1
TAP_TLV_CHANNEL = 3
TAP_TLV_LQI = 10


def build_tap_header(channel, rssi, lqi):
    """Build IEEE 802.15.4 TAP header with TLVs for Wireshark."""
    tlvs = b""
    # FCS Type: 2-byte FCS (type 0, length 1, value 1)
    tlvs += struct.pack("<HHB", TAP_TLV_FCS_TYPE, 1, 1)
    tlvs += b"\x00" * 3  # pad to 4-byte boundary
    # RSS (dBm): float32
    tlvs += struct.pack("<HHf", TAP_TLV_RSS, 4, float(rssi))
    # Channel: IEEE 802.15.4 channel (uint16 page, uint16 number, uint16 frequency)
    freq = 2405 + (channel - 11) * 5
    tlvs += struct.pack("<HH HHH", TAP_TLV_CHANNEL, 6, 0, channel, freq)
    tlvs += b"\x00" * 2  # pad to 4-byte boundary
    # LQI: uint32
    tlvs += struct.pack("<HHI", TAP_TLV_LQI, 4, lqi)

    # TAP header: version (0) + length (header_len includes the 4-byte version+length field)
    header_len = 4 + len(tlvs)
    return struct.pack("<HH", 0, header_len) + tlvs


def write_pcap_header(f):
    """Write global PCAP file header."""
    f.write(struct.pack("<IHHIIII",
        PCAP_MAGIC,
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        0,          # thiszone
        0,          # sigfigs
        65535,      # snaplen
        PCAP_LINKTYPE_IEEE802154_TAP
    ))
    f.flush()


def write_pcap_record(f, tap_header, frame_data):
    """Write a single PCAP packet record."""
    ts = time.time()
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    total = tap_header + frame_data
    caplen = len(total)
    f.write(struct.pack("<IIII", ts_sec, ts_usec, caplen, caplen))
    f.write(total)
    f.flush()


def parse_802154_mac(data):
    """Parse basic IEEE 802.15.4 MAC header fields."""
    if len(data) < 2:
        return {}

    fcf = struct.unpack_from("<H", data, 0)[0]
    frame_type = fcf & 0x07
    security_enabled = bool(fcf & 0x08)
    frame_pending = bool(fcf & 0x10)
    ack_request = bool(fcf & 0x20)
    pan_id_compress = bool(fcf & 0x40)
    dest_addr_mode = (fcf >> 10) & 0x03
    frame_version = (fcf >> 12) & 0x03
    src_addr_mode = (fcf >> 14) & 0x03

    FRAME_TYPES = {0: "Beacon", 1: "Data", 2: "Ack", 3: "Command",
                   4: "Reserved", 5: "Multipurpose", 6: "Fragment", 7: "Extended"}

    result = {
        "frame_type": FRAME_TYPES.get(frame_type, f"Unknown({frame_type})"),
        "frame_type_id": frame_type,
        "security": security_enabled,
        "ack_req": ack_request,
        "pan_compress": pan_id_compress,
        "version": frame_version,
        "dest_addr_mode": dest_addr_mode,
        "src_addr_mode": src_addr_mode,
    }

    offset = 3  # FCF (2) + seq (1)
    if len(data) > 2:
        result["seq"] = data[2]

    # Destination PAN + address
    if dest_addr_mode > 0 and offset + 2 <= len(data):
        result["dst_pan"] = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        if dest_addr_mode == 2 and offset + 2 <= len(data):
            result["dst_addr"] = f"0x{struct.unpack_from('<H', data, offset)[0]:04X}"
            offset += 2
        elif dest_addr_mode == 3 and offset + 8 <= len(data):
            addr_bytes = data[offset:offset+8]
            result["dst_addr"] = ":".join(f"{b:02X}" for b in reversed(addr_bytes))
            offset += 8

    # Source PAN + address
    if src_addr_mode > 0:
        if not pan_id_compress and offset + 2 <= len(data):
            result["src_pan"] = struct.unpack_from("<H", data, offset)[0]
            offset += 2
        elif pan_id_compress and "dst_pan" in result:
            result["src_pan"] = result["dst_pan"]

        if src_addr_mode == 2 and offset + 2 <= len(data):
            result["src_addr"] = f"0x{struct.unpack_from('<H', data, offset)[0]:04X}"
            offset += 2
        elif src_addr_mode == 3 and offset + 8 <= len(data):
            addr_bytes = data[offset:offset+8]
            result["src_addr"] = ":".join(f"{b:02X}" for b in reversed(addr_bytes))
            offset += 8

    result["header_len"] = offset
    if offset < len(data):
        result["payload_len"] = len(data) - offset

    return result


def read_frame(ser):
    """Read one framed packet from serial. Returns (channel, rssi, lqi, data) or None."""
    # Sync to 0xAA
    while True:
        b = ser.read(1)
        if len(b) == 0:
            return None
        if b[0] == SYNC_BYTE:
            break

    # Read length
    b = ser.read(1)
    if len(b) == 0:
        return None
    total_len = b[0]
    if total_len < 4 or total_len > 130:
        return None

    # Read CH, RSSI, LQI + frame data + checksum
    remaining = ser.read(total_len + 1)  # +1 for checksum
    if len(remaining) < total_len + 1:
        return None

    # Verify checksum
    chk = total_len
    for i in range(total_len):
        chk ^= remaining[i]
    if chk != remaining[total_len]:
        return None

    channel = remaining[0]
    rssi = struct.unpack_from("b", remaining, 1)[0]
    lqi = remaining[2]
    frame_data = bytes(remaining[3:total_len])

    if channel == 0:
        return None

    return channel, rssi, lqi, frame_data


def main():
    parser = argparse.ArgumentParser(description="Litewave 802.15.4 Sniffer Capture Tool")
    parser.add_argument("--port", default="/dev/cu.usbmodem1101", help="Serial port")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    parser.add_argument("--pcap", help="Write PCAP file (use '-' for stdout/pipe to Wireshark)")
    parser.add_argument("--json", help="Write frames as JSON lines to file")
    parser.add_argument("--quiet", action="store_true", help="Suppress live console output")
    args = parser.parse_args()

    # Open serial
    try:
        ser = serial.Serial(args.port, args.baud, timeout=1)
    except serial.SerialException as e:
        print(f"Error opening {args.port}: {e}", file=sys.stderr)
        sys.exit(1)

    # Open output files
    pcap_file = None
    if args.pcap:
        if args.pcap == "-":
            pcap_file = sys.stdout.buffer
        else:
            pcap_file = open(args.pcap, "wb")
        write_pcap_header(pcap_file)

    json_file = None
    if args.json:
        json_file = open(args.json, "w")

    # Stats
    frame_count = 0
    channel_counts = defaultdict(int)
    addr_set = set()

    if not args.quiet:
        print("Listening on", args.port, file=sys.stderr)
        print("Press Ctrl+C to stop\n", file=sys.stderr)

    try:
        while True:
            result = read_frame(ser)
            if result is None:
                continue

            channel, rssi, lqi, frame_data = result
            frame_count += 1
            channel_counts[channel] += 1

            # Parse MAC header
            mac = parse_802154_mac(frame_data)

            # Track addresses
            for key in ("src_addr", "dst_addr"):
                if key in mac:
                    addr_set.add(mac[key])

            # Console output
            if not args.quiet:
                ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                src = mac.get("src_addr", "?")
                dst = mac.get("dst_addr", "?")
                ftype = mac.get("frame_type", "?")
                pan = f"PAN:0x{mac['dst_pan']:04X}" if "dst_pan" in mac else ""
                sec = " [SEC]" if mac.get("security") else ""
                plen = mac.get("payload_len", 0)

                print(f"[{ts}] ch:{channel:2d} rssi:{rssi:4d} lqi:{lqi:3d} "
                      f"{ftype:12s} {src:>20s} -> {dst:<20s} {pan} "
                      f"len:{len(frame_data):3d} payload:{plen:3d}{sec}",
                      file=sys.stderr)

                # Hex dump of payload (after MAC header)
                hdr_len = mac.get("header_len", 0)
                if hdr_len < len(frame_data):
                    payload = frame_data[hdr_len:]
                    hex_str = " ".join(f"{b:02X}" for b in payload[:48])
                    if len(payload) > 48:
                        hex_str += " ..."
                    print(f"           payload: {hex_str}", file=sys.stderr)

            # PCAP output
            if pcap_file:
                tap_hdr = build_tap_header(channel, rssi, lqi)
                write_pcap_record(pcap_file, tap_hdr, frame_data)

            # JSON output
            if json_file:
                record = {
                    "time": time.time(),
                    "channel": channel,
                    "rssi": rssi,
                    "lqi": lqi,
                    "frame_hex": frame_data.hex(),
                    "mac": mac,
                }
                json_file.write(json.dumps(record) + "\n")
                json_file.flush()

    except KeyboardInterrupt:
        pass
    finally:
        # Print summary
        print(f"\n--- Capture Summary ---", file=sys.stderr)
        print(f"Total frames: {frame_count}", file=sys.stderr)
        print(f"Channels seen:", file=sys.stderr)
        for ch in sorted(channel_counts.keys()):
            print(f"  ch {ch:2d}: {channel_counts[ch]:6d} frames", file=sys.stderr)
        print(f"Unique addresses: {len(addr_set)}", file=sys.stderr)
        for addr in sorted(addr_set):
            print(f"  {addr}", file=sys.stderr)

        ser.close()
        if pcap_file and args.pcap != "-":
            pcap_file.close()
        if json_file:
            json_file.close()


if __name__ == "__main__":
    main()
