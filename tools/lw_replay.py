#!/usr/bin/env python3
"""
Litewave Token Replay — send ON/OFF with tokens from the command line.

Usage:
    # Replay ON:
    python3 lw_replay.py on 0xFB 949B16B63E32024A9DD73E03604D

    # Replay OFF:
    python3 lw_replay.py off 0xFD 9ACC50F8E109757695C384C4EA74

    # Arguments: command, sequence_number, 14-byte_token_hex
"""

import argparse
import struct
import sys
import time

import serial

SYNC_BYTE = 0xBB
DEFAULT_CHANNEL = 26
DEFAULT_PAN = 0x3B71
MULTICAST_DST = 0xFFF0
TX_REPEATS = 5
TX_DELAY_MS = 20


def build_litewave_frame(seq, pan_id, dst, token_bytes):
    """Build a Litewave 802.15.4 frame."""
    frame = bytearray()
    frame.append(0x01)  # FCF lo
    frame.append(0x18)  # FCF hi
    frame.append(seq)
    frame.append(pan_id & 0xFF)
    frame.append((pan_id >> 8) & 0xFF)
    frame.append(dst & 0xFF)
    frame.append((dst >> 8) & 0xFF)
    frame.append(0x09)  # TTL
    frame.append(0x00)  # Command type
    frame.extend(token_bytes)
    frame.append(0xAE)  # Trailing byte 1
    frame.append(0x09)  # Trailing byte 2
    return bytes(frame)


def send_frame(ser, channel, frame_data, repeats=1, delay_ms=20):
    """Send a frame to the transmitter firmware."""
    frame_len = len(frame_data)
    chk = frame_len ^ channel ^ repeats ^ delay_ms
    for b in frame_data:
        chk ^= b
    packet = bytes([SYNC_BYTE, frame_len, channel, repeats, delay_ms]) + frame_data + bytes([chk])
    ser.write(packet)
    ser.flush()
    line = ser.readline().decode("utf-8", errors="replace").strip()
    return line


def main():
    parser = argparse.ArgumentParser(description="Litewave Token Replay")
    parser.add_argument("command", choices=["on", "off"],
                        help="on or off")
    parser.add_argument("sequence", type=lambda x: int(x, 0),
                        help="Sequence number (e.g., 0xFB)")
    parser.add_argument("token",
                        help="14-byte token as 28 hex chars (e.g., 949B16B63E32024A9DD73E03604D)")
    parser.add_argument("--port", default="/dev/cu.usbmodem1101")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--channel", type=int, default=DEFAULT_CHANNEL)
    parser.add_argument("--pan", type=lambda x: int(x, 0), default=DEFAULT_PAN)
    parser.add_argument("--dst", type=lambda x: int(x, 0), default=MULTICAST_DST,
                        help="Destination address (default: 0xFFF0 multicast)")
    parser.add_argument("--repeats", type=int, default=TX_REPEATS)
    args = parser.parse_args()

    token_hex = args.token.replace(" ", "").replace(":", "")
    if len(token_hex) != 28:
        print(f"Error: token must be 14 bytes (28 hex chars), got {len(token_hex)}", file=sys.stderr)
        sys.exit(1)
    token_bytes = bytes.fromhex(token_hex)

    frame = build_litewave_frame(args.sequence, args.pan, args.dst, token_bytes)

    print(f"Sending {args.command.upper()}: seq=0x{args.sequence:02X} dst=0x{args.dst:04X} token={token_hex}", file=sys.stderr)
    print(f"  Frame ({len(frame)}b): {frame.hex()}", file=sys.stderr)

    ser = serial.Serial(args.port, args.baud, timeout=2)
    time.sleep(0.5)

    resp = send_frame(ser, args.channel, frame, repeats=args.repeats, delay_ms=TX_DELAY_MS)
    print(f"  TX result: {resp}", file=sys.stderr)

    ser.close()
    print("Done.", file=sys.stderr)


if __name__ == "__main__":
    main()
