#!/usr/bin/env python3
"""
Capture ALL raw 802.15.4 frames on channel 26 during a control group save.
Saves complete raw frame bytes for later analysis, not just token fields.
"""

import serial
import struct
import time
import json
import sys

SYNC_BYTE = 0xAA
PORT = '/dev/cu.usbmodem1101'
OUTFILE = '/tmp/raw_frames_control_group.json'


def read_frame(ser):
    while True:
        b = ser.read(1)
        if len(b) == 0:
            return None
        if b[0] == SYNC_BYTE:
            break
    raw_len = ser.read(1)
    if len(raw_len) == 0:
        return None
    total_len = raw_len[0]
    if total_len < 4 or total_len > 130:
        return None
    remaining = ser.read(total_len + 1)
    if len(remaining) < total_len + 1:
        return None
    chk = total_len
    for i in range(total_len):
        chk ^= remaining[i]
    if (chk & 0xFF) != remaining[total_len]:
        return None
    channel = remaining[0]
    rssi = struct.unpack_from("b", remaining, 1)[0]
    lqi = remaining[2]
    frame_data = bytes(remaining[3:total_len])
    return channel, rssi, lqi, frame_data


def main():
    ser = serial.Serial(PORT, 115200, timeout=1)
    print(f"Listening on {PORT} for 802.15.4 frames on channel 26...")
    print(f"Output: {OUTFILE}")
    print(f"Press Ctrl+C to stop\n")

    frames = []
    count = 0
    start = time.time()

    try:
        while True:
            result = read_frame(ser)
            if result is None:
                continue
            channel, rssi, lqi, frame_data = result
            count += 1
            elapsed = time.time() - start

            frame_hex = frame_data.hex()
            fcf = struct.unpack_from("<H", frame_data, 0)[0] if len(frame_data) >= 2 else 0
            dsn = frame_data[2] if len(frame_data) >= 3 else -1

            entry = {
                'time': round(elapsed, 3),
                'channel': channel,
                'rssi': rssi,
                'lqi': lqi,
                'len': len(frame_data),
                'fcf': f"0x{fcf:04X}",
                'dsn': dsn,
                'raw': frame_hex,
            }
            frames.append(entry)

            # Print summary
            ft = fcf & 0x07
            sec = (fcf >> 3) & 1
            ft_names = {0: 'BCN', 1: 'DAT', 2: 'ACK', 3: 'CMD'}
            ft_name = ft_names.get(ft, f'?{ft}')
            print(f"[{elapsed:7.1f}s] #{count:4d} FCF={fcf:04X}({ft_name} sec={sec}) DSN={dsn:3d} len={len(frame_data):3d} {frame_hex[:40]}{'...' if len(frame_hex)>40 else ''}")

    except KeyboardInterrupt:
        pass

    ser.close()
    elapsed = time.time() - start
    print(f"\nCaptured {len(frames)} frames in {elapsed:.1f}s")

    with open(OUTFILE, 'w') as f:
        json.dump(frames, f, indent=2)
    print(f"Saved to {OUTFILE}")


if __name__ == '__main__':
    main()
