#!/usr/bin/env python3
"""
Direct Raw Litewave Button Capture & Test Replay Tool
Captures exact byte-for-byte 802.15.4 frames from Sense+ switch button presses,
then flashes the transmitter and verifies execution against the downlight.
"""

import sys
import time
import struct
import serial
from capture_and_provision import flash_firmware, select_serial_port
from ltpdu_v3 import LtpduV3Session
from lw_replay import send_frame

SYNC_BYTE = 0xAA
PORT = select_serial_port() or "/dev/cu.usbmodem1101"
LIGHT_HOST = "fd31:e7fd:cbed:1:b5e5:2e37:1f2b:e274"
LIGHT_NAME = "Nanoleaf DL 789-6223"
LIGHT_CODE = "1640-700-5590"


def read_raw_frame(ser):
    while True:
        b = ser.read(1)
        if not b:
            return None
        if b[0] == SYNC_BYTE:
            break
    raw_len = ser.read(1)
    if not raw_len:
        return None
    tot_len = raw_len[0]
    if tot_len < 4 or tot_len > 130:
        return None
    rem = ser.read(tot_len + 1)
    if len(rem) < tot_len + 1:
        return None
    chk = tot_len
    for i in range(tot_len):
        chk ^= rem[i]
    if (chk & 0xFF) != rem[tot_len]:
        return None
    ch = rem[0]
    rssi = struct.unpack_from("b", rem, 1)[0]
    lqi = rem[2]
    data = rem[3:tot_len]
    return ch, rssi, lqi, data


def capture_button_raw(ser, label, timeout=25):
    print(f"\n{'━'*50}")
    print(f"  Listening for: {label}")
    print(f"  >>> Press the {label} button on the Sense+ switch now <<<")
    print(f"{'━'*50}")
    ser.reset_input_buffer()
    start = time.time()
    frames = []
    while time.time() - start < timeout:
        res = read_raw_frame(ser)
        if res:
            ch, rssi, lqi, data = res
            if ch == 26 and len(data) >= 15:
                fcf = struct.unpack_from("<H", data, 0)[0]
                if fcf == 0x1801 or fcf == 0x0118:
                    dst_pan = struct.unpack_from("<H", data, 3)[0]
                    dst_addr = struct.unpack_from("<H", data, 5)[0]
                    dsn = data[2]
                    print(f"  Captured frame: DSN=0x{dsn:02X} PAN=0x{dst_pan:04X} DST=0x{dst_addr:04X} len={len(data)} (RSSI={rssi})")
                    print(f"    Raw bytes: {data.hex()}")
                    frames.append(data)
                    # Once we have 3-5 retransmits of the burst, return
                    if len(frames) >= 3:
                        break
    if not frames:
        print(f"  Timeout waiting for {label} button.")
        return None
    # Return the frame with multicast 0xFFF0 if present, else first frame
    for f in frames:
        if len(f) >= 7 and struct.unpack_from("<H", f, 5)[0] == 0xFFF0:
            return f
    return frames[0]


def main():
    print("=" * 60)
    print("  Raw Litewave Capture & Test Replay")
    print("=" * 60)

    # 1. Ensure sniffer is flashed
    print(f"\nStep 1: Flashing Sniffer to {PORT}...")
    flash_firmware(PORT, "sniffer")

    ser = serial.Serial(PORT, 115200, timeout=0.1)
    time.sleep(0.5)

    # 2. Capture ON button
    on_frame = capture_button_raw(ser, "ON (usually left/top)")
    if not on_frame:
        ser.close()
        sys.exit(1)

    time.sleep(1.0)

    # 3. Capture OFF button
    off_frame = capture_button_raw(ser, "OFF (usually right/bottom)")
    if not off_frame:
        ser.close()
        sys.exit(1)

    ser.close()

    print(f"\n{'━'*60}")
    print("  Captured Frames Summary:")
    print(f"  ON  Frame ({len(on_frame)}B): {on_frame.hex()}")
    print(f"  OFF Frame ({len(off_frame)}B): {off_frame.hex()}")
    print(f"{'━'*60}")

    # 4. Flash Transmitter
    print(f"\nStep 2: Flashing Transmitter to {PORT}...")
    flash_firmware(PORT, "transmitter")

    # 5. Check Initial Light State
    session = LtpduV3Session(LIGHT_HOST, 12566)
    session.pair(LIGHT_NAME, LIGHT_CODE)
    st = session.get("lb/0/oo")
    initial_on = (st[1] == b"\x01") if isinstance(st, tuple) else False
    print(f"\nInitial light state: {'ON' if initial_on else 'OFF'}")
    session.unpair()

    ser_tx = serial.Serial(PORT, 115200, timeout=1)
    time.sleep(0.5)

    if initial_on:
        print("\nTesting OFF frame replay...")
        send_frame(ser_tx, 26, off_frame, repeats=10, delay_ms=10)
        time.sleep(1)
        session = LtpduV3Session(LIGHT_HOST, 12566)
        session.pair(LIGHT_NAME, LIGHT_CODE)
        st = session.get("lb/0/oo")
        print(f"State after OFF replay: {'ON' if st[1] == b'\x01' else 'OFF'}")
        session.unpair()

        print("\nTesting ON frame replay...")
        send_frame(ser_tx, 26, on_frame, repeats=10, delay_ms=10)
        time.sleep(1)
        session = LtpduV3Session(LIGHT_HOST, 12566)
        session.pair(LIGHT_NAME, LIGHT_CODE)
        st = session.get("lb/0/oo")
        print(f"State after ON replay: {'ON' if st[1] == b'\x01' else 'OFF'}")
        session.unpair()
    else:
        print("\nTesting ON frame replay...")
        send_frame(ser_tx, 26, on_frame, repeats=10, delay_ms=10)
        time.sleep(1)
        session = LtpduV3Session(LIGHT_HOST, 12566)
        session.pair(LIGHT_NAME, LIGHT_CODE)
        st = session.get("lb/0/oo")
        print(f"State after ON replay: {'ON' if st[1] == b'\x01' else 'OFF'}")
        session.unpair()

        print("\nTesting OFF frame replay...")
        send_frame(ser_tx, 26, off_frame, repeats=10, delay_ms=10)
        time.sleep(1)
        session = LtpduV3Session(LIGHT_HOST, 12566)
        session.pair(LIGHT_NAME, LIGHT_CODE)
        st = session.get("lb/0/oo")
        print(f"State after OFF replay: {'ON' if st[1] == b'\x01' else 'OFF'}")
        session.unpair()

    ser_tx.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
