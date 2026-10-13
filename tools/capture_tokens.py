#!/usr/bin/env python3
"""
Interactive Litewave token capture tool.
Connects to the ESP32-C6 sniffer via USB, guides the user through
capturing ON and OFF tokens, and outputs ESPHome config.

Usage: python3 capture_tokens.py [--port /dev/cu.usbmodem1101] [--group-name kitchen]
"""

import argparse
import serial
import struct
import sys
import time


SYNC_BYTE = 0xAA
LITEWAVE_PAN = 0x3B71
LITEWAVE_DST = 0xFFF0


def find_serial_port():
    """Try common ESP32-C6 serial port names."""
    import glob
    candidates = glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*")
    if candidates:
        return candidates[0]
    return None


def read_frame(ser):
    """Read one binary-framed packet from the sniffer."""
    # Sync
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

    remaining = ser.read(total_len + 1)  # +1 for checksum
    if len(remaining) < total_len + 1:
        return None

    # Verify checksum
    chk = total_len
    for i in range(total_len):
        chk ^= remaining[i]
    if (chk & 0xFF) != remaining[total_len]:
        return None

    channel = remaining[0]
    rssi = struct.unpack_from("b", remaining, 1)[0]
    lqi = remaining[2]
    frame_data = bytes(remaining[3:total_len])
    if channel == 0:
        return None
    return channel, rssi, lqi, frame_data


def parse_litewave_frame(frame_data):
    """
    Parse an 802.15.4 frame and extract Litewave token if it matches.
    Returns (dsn, token_hex) or None.
    
    Frame layout: FCF(2) + DSN(1) + dst_pan(2) + dst_addr(2) + payload...
    Payload: TTL(1) + 0x00(1) + token(14) + trailer(2)
    
    The DSN (Data Sequence Number) is the value that changes per button press
    and is what ESPHome needs as the "sequence" config value.
    """
    if len(frame_data) < 10:
        return None

    # Frame Control Field (2 bytes, little-endian)
    fcf = struct.unpack_from("<H", frame_data, 0)[0]
    frame_type = fcf & 0x07
    if frame_type != 1:  # Data frame
        return None

    # MAC DSN at offset 2 — this is the sequence number ESPHome uses
    dsn = frame_data[2]

    # Parse addressing
    dst_mode = (fcf >> 10) & 0x03
    src_mode = (fcf >> 14) & 0x03
    pan_compress = (fcf >> 6) & 0x01

    offset = 3  # after FCF + DSN

    # Destination PAN + address
    dst_pan = None
    dst_addr = None
    if dst_mode == 2:  # Short address
        if offset + 4 > len(frame_data):
            return None
        dst_pan = struct.unpack_from("<H", frame_data, offset)[0]
        offset += 2
        dst_addr = struct.unpack_from("<H", frame_data, offset)[0]
        offset += 2
    elif dst_mode == 3:  # Extended address
        if offset + 10 > len(frame_data):
            return None
        dst_pan = struct.unpack_from("<H", frame_data, offset)[0]
        offset += 2
        offset += 8  # skip 8-byte EUI-64
    else:
        return None

    # Check Litewave PAN and destination
    if dst_pan != LITEWAVE_PAN:
        return None
    if dst_mode == 2 and dst_addr != LITEWAVE_DST:
        return None

    # Source PAN + address (skip)
    if src_mode == 2:
        if not pan_compress:
            offset += 2  # source PAN
        offset += 2  # short addr
    elif src_mode == 3:
        if not pan_compress:
            offset += 2
        offset += 8

    # Payload starts at offset
    payload = frame_data[offset:]

    # Litewave payload: at least 16 bytes (TTL + 0x00 + 14-byte token)
    if len(payload) < 16:
        return None

    cmd_type = payload[1]
    token = payload[2:16]

    # Sanity: cmd_type should be 0x00 for normal ON/OFF commands
    if cmd_type != 0x00:
        return None

    return dsn, token.hex().upper()


def capture_command(ser, label, timeout=30, debug=False):
    """
    Wait for a Litewave command, capturing the first frame of a burst.
    Returns (sequence, token_hex) or None.
    """
    print(f"\n  Listening for {label} command...")
    print(f"  Press the {label} button on the Sense+ switch now.")

    ser.reset_input_buffer()
    start = time.time()
    captured = None
    quiet_since = None
    frame_count = 0

    while time.time() - start < timeout:
        frame = read_frame(ser)
        if frame is None:
            if captured and quiet_since and (time.time() - quiet_since > 0.5):
                break
            continue

        channel, rssi, lqi, frame_data = frame
        frame_count += 1

        if debug:
            print(f"    frame #{frame_count}: ch={channel} rssi={rssi} len={len(frame_data)} hex={frame_data.hex()}")

        result = parse_litewave_frame(frame_data)
        if result is None:
            if debug and frame_count <= 20:
                # Show why it was rejected
                if len(frame_data) >= 2:
                    fcf = struct.unpack_from("<H", frame_data, 0)[0]
                    ft = fcf & 0x07
                    if ft != 1:
                        print(f"      rejected: frame_type={ft} (not data)")
                    elif len(frame_data) >= 7:
                        dst_pan = struct.unpack_from("<H", frame_data, 3)[0]
                        dst_addr = struct.unpack_from("<H", frame_data, 5)[0]
                        print(f"      rejected: pan=0x{dst_pan:04X} dst=0x{dst_addr:04X}")
            continue

        seq, token_hex = result

        if captured is None:
            captured = (seq, token_hex)
            print(f"  Captured! seq=0x{seq:02X} token={token_hex} (RSSI={rssi})")
            quiet_since = time.time()
        else:
            quiet_since = time.time()

    # Debounce: drain any trailing frames so the next capture doesn't pick up
    # a second burst from the same physical press
    if captured:
        time.sleep(1.5)
        ser.reset_input_buffer()

    if not captured:
        print(f"  ({frame_count} frames received, none matched Litewave PAN 0x{LITEWAVE_PAN:04X} dst 0x{LITEWAVE_DST:04X})")

    return captured


def main():
    parser = argparse.ArgumentParser(description="Interactive Litewave token capture")
    parser.add_argument("--port", help="Serial port (auto-detected if omitted)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default 115200)")
    parser.add_argument("--group-name", default="room", help="ESPHome group name (default: room)")
    parser.add_argument("--debug", action="store_true", help="Show all received frames")
    args = parser.parse_args()

    port = args.port or find_serial_port()
    if not port:
        print("No serial port found. Connect the ESP32-C6 sniffer and try again,")
        print("or specify with --port /dev/cu.usbmodemXXXX")
        sys.exit(1)

    print(f"╔══════════════════════════════════════════════╗")
    print(f"║   Litewave Token Capture Tool                ║")
    print(f"╚══════════════════════════════════════════════╝")
    print(f"\n  Sniffer: {port} @ {args.baud}")

    try:
        ser = serial.Serial(port, args.baud, timeout=0.1)
    except serial.SerialException as e:
        print(f"\n  Could not open {port}: {e}")
        sys.exit(1)

    # Flush any stale data
    time.sleep(0.5)
    ser.reset_input_buffer()
    print(f"  Port open. Sniffer listens on channel 26 (no output until frames arrive).")

    # === Capture ON ===
    print(f"\n{'─'*50}")
    print(f"  Step 1: Capture ON command")
    print(f"{'─'*50}")
    on_result = capture_command(ser, "ON", debug=args.debug)
    if not on_result:
        print("\n  Timeout waiting for ON command. Make sure:")
        print("  - The sniffer firmware is flashed to the ESP32-C6")
        print("  - The Sense+ switch is paired with lights")
        print("  - You pressed the ON button (usually left)")
        ser.close()
        sys.exit(1)

    on_seq, on_token = on_result

    # === Capture OFF ===
    print(f"\n{'─'*50}")
    print(f"  Step 2: Capture OFF command")
    print(f"{'─'*50}")
    off_result = capture_command(ser, "OFF", debug=args.debug)
    if not off_result:
        print("\n  Timeout waiting for OFF command.")
        ser.close()
        sys.exit(1)

    off_seq, off_token = off_result
    ser.close()

    # === Output ===
    group_name = args.group_name

    print(f"\n{'━'*50}")
    print(f"  Capture complete!")
    print(f"{'━'*50}")
    print(f"\n  ON:  seq=0x{on_seq:02X}  token={on_token}")
    print(f"  OFF: seq=0x{off_seq:02X}  token={off_token}")

    yaml_block = f"""
# ESPHome Litewave group config — paste into your YAML
litewave:
  groups:
    - id: {group_name}
      on_sequence: 0x{on_seq:02X}
      on_token: "{on_token}"
      off_sequence: 0x{off_seq:02X}
      off_token: "{off_token}"
"""

    print(f"\n{'━'*50}")
    print(yaml_block)
    print(f"{'━'*50}")

    # Also save to file
    filename = f"captured_{group_name}.yaml"
    with open(filename, "w") as f:
        f.write(yaml_block)
    print(f"\n  Saved to {filename}")


if __name__ == "__main__":
    main()
