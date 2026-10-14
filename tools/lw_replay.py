#!/usr/bin/env python3
"""
Litewave Token Replay — send ON/OFF/DIM with tokens from the command line.

Usage:
    # Replay ON:
    python3 lw_replay.py on 0xFB 949B16B63E32024A9DD73E03604D

    # Replay OFF:
    python3 lw_replay.py off 0xFD 9ACC50F8E109757695C384C4EA74

    # Replay across all 802.15.4 channels (11-26) to find the light's channel:
    python3 lw_replay.py on 0xFB 949B16B63E32024A9DD73E03604D --all-channels
"""

import argparse
import glob
import struct
import sys
import time

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("Error: pyserial is required. Run: pip install pyserial", file=sys.stderr)
    sys.exit(1)

SYNC_BYTE = 0xBB
MULTICAST_DST = 0xFFF0
TX_REPEATS = 5
TX_DELAY_MS = 20


def select_serial_port(explicit_port=None):
    if explicit_port:
        return explicit_port
    try:
        comports = serial.tools.list_ports.comports()
        candidates = [p for p in comports if "bluetooth" not in p.device.lower() and "debug-console" not in p.device.lower()]
    except Exception:
        paths = glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/cu.usbserial*") + glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*")
        candidates = [type("Port", (), {"device": p, "description": "Serial Port"})() for p in paths]

    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0].device
    print("Multiple serial ports found:")
    for idx, p in enumerate(candidates):
        print(f"  [{idx + 1}] {p.device} ({p.description})")
    choice = input(f"Select port (1-{len(candidates)}) [1]: ").strip()
    idx = int(choice) - 1 if choice.isdigit() else 0
    return candidates[idx].device


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
    parser.add_argument("command", choices=["on", "off", "dim_up", "dim_down", "dim+", "dim-"],
                        help="command action")
    parser.add_argument("sequence", type=lambda x: int(x, 0),
                        help="Sequence number (e.g., 0xFB or 251)")
    parser.add_argument("token",
                        help="14-byte token as 28 hex chars (e.g., 949B16B63E32024A9DD73E03604D)")
    parser.add_argument("--port", default=None, help="Serial port (auto-detected if omitted)")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--channel", type=int, default=26, help="Radio channel (11-26, default 26)")
    parser.add_argument("--all-channels", action="store_true",
                        help="Sweep across all channels 11-26 (useful if light Thread channel is unknown)")
    parser.add_argument("--pan", type=lambda x: int(x, 0), required=True,
                        help="2-byte PAN ID (e.g. 0x1234 or from Nanoleaf cloud/app)")
    parser.add_argument("--dst", type=lambda x: int(x, 0), default=MULTICAST_DST,
                        help="Destination address (default: 0xFFF0 multicast)")
    parser.add_argument("--repeats", type=int, default=TX_REPEATS)
    args = parser.parse_args()

    port = select_serial_port(args.port)
    if not port:
        print("Error: No serial port found. Plug in ESP32-C6 transmitter or specify --port.", file=sys.stderr)
        sys.exit(1)

    token_hex = args.token.replace(" ", "").replace(":", "").replace("0x", "")
    if len(token_hex) != 28:
        print(f"Error: token must be 14 bytes (28 hex chars), got {len(token_hex)}", file=sys.stderr)
        sys.exit(1)
    token_bytes = bytes.fromhex(token_hex)

    frame = build_litewave_frame(args.sequence, args.pan, args.dst, token_bytes)

    print(f"Port: {port}")
    print(f"Sending {args.command.upper()}: seq=0x{args.sequence:02X} dst=0x{args.dst:04X} token={token_hex}")
    print(f"  Frame ({len(frame)}b): {frame.hex()}")

    ser = serial.Serial(port, args.baud, timeout=2)
    time.sleep(0.5)

    if args.all_channels:
        print("Sweeping across channels 11-26...")
        for ch in range(11, 27):
            resp = send_frame(ser, ch, frame, repeats=args.repeats, delay_ms=TX_DELAY_MS)
            print(f"  CH {ch:2d} -> TX result: {resp}")
            time.sleep(0.1)
    else:
        resp = send_frame(ser, args.channel, frame, repeats=args.repeats, delay_ms=TX_DELAY_MS)
        print(f"  Channel {args.channel} -> TX result: {resp}")

    ser.close()
    print("Done.")


if __name__ == "__main__":
    main()
