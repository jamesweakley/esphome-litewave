#!/usr/bin/env python3
"""
Unified Litewave capture and provisioning tool.

Combines BLE shared-secret writing with 802.15.4 token capture into a single
guided flow. Captures ON, OFF, DIM+, and DIM- tokens from a Sense+ switch.

Usage:
    # Scan for nearby Sense+ switches (hold ON + OFF for 3 seconds first):
    python3 capture_and_provision.py --scan-switches

    # Full flow: write secret to switch, then capture 4 buttons
    python3 capture_and_provision.py \\
        --switch-name "Nanoleaf Wireless SW 1D9" \\
        --switch-code "0242-362-0007" \\
        --secret 1234 \\
        --group-name kitchen

    # Capture only (skip BLE write, e.g. secret already on the switch)
    python3 capture_and_provision.py --capture-only --group-name kitchen

    # Generate a random secret
    python3 capture_and_provision.py \\
        --switch-name "Nanoleaf Wireless SW 1D9" \\
        --switch-code "0242-362-0007" \\
        --group-name kitchen

Note for BLE operations:
    Hold the ON and OFF buttons on the Sense+ switch simultaneously for 3 seconds
    until the white LED flashes to put it into BLE advertising / pairing mode.

Requirements:
    pip install bleak cryptography pyserial
"""

import argparse
import asyncio
import glob
import hashlib
import os
import struct
import sys
import time

import serial

# ---------------------------------------------------------------------------
# BLE session for writing shared secret to Sense+ switch
# ---------------------------------------------------------------------------

ENCRYPTION_SETUP = "6d2adfda-9aea-11ea-bb37-0242ac130002"
ENCRYPTED_CHAR   = "6d2adda0-9aea-11ea-bb37-0242ac130002"

SALT_KEY_NEW = bytes.fromhex(
    "bca9e39738e2611c25d243c985d3c592ccbee330e077b89d7978f5fc785cb5e8"
)
SALT_IV_NEW = bytes.fromhex(
    "41e2e9eb5e5fa56e800e346d8c2b600742eb49839626faecdc37fb94a3a3c202"
)


class LegacyBleSession:
    def __init__(self, client):
        self.client = client
        self.encrypt_cipher = None
        self.decrypt_cipher = None
        self._shared_secret = None

    def _init_ciphers(self, shared_secret, use_new_salts=True):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        salt_key = SALT_KEY_NEW if use_new_salts else b"AES-NL-OPENAPI-KEY"
        salt_iv = SALT_IV_NEW if use_new_salts else b"AES-NL-OPENAPI-IV"
        key = hashlib.sha1(salt_key + shared_secret).digest()[:16]
        iv = hashlib.sha1(salt_iv + shared_secret).digest()[:16]
        self.encrypt_cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        self.decrypt_cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()

    def encrypt(self, data):
        return self.encrypt_cipher.update(data)

    def decrypt(self, data):
        return self.decrypt_cipher.update(data)

    async def key_exchange(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey,
        )
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        await self.client.write_gatt_char(ENCRYPTION_SETUP, pub, response=True)
        their_pub_raw = bytes(
            await self.client.read_gatt_char(ENCRYPTION_SETUP)
        )
        their_pub = X25519PublicKey.from_public_bytes(their_pub_raw)
        self._shared_secret = priv.exchange(their_pub)
        return True

    async def send_encrypted_setup(self, data):
        encrypted = self.encrypt(data)
        await self.client.write_gatt_char(
            ENCRYPTION_SETUP, encrypted, response=True
        )
        response = await self.client.read_gatt_char(ENCRYPTION_SETUP)
        return self.decrypt(bytes(response))

    async def send_encrypted(self, data):
        encrypted = self.encrypt(data)
        await self.client.write_gatt_char(
            ENCRYPTED_CHAR, encrypted, response=True
        )
        response = await self.client.read_gatt_char(ENCRYPTED_CHAR)
        return self.decrypt(bytes(response))


def _build_ble_ltpdu_cmd(endpoint, value=None, method=0):
    ep = endpoint.encode("utf-8")
    tlv = struct.pack("!HH", 1, len(ep)) + ep
    tlv += struct.pack("!HH", 2, len(value) if value else 0)
    if value:
        tlv += value
    tlv += struct.pack("!HH", 4, 1) + bytes([method])
    return tlv


_coap_msg_id = 0


def _wrap_coap(ltpdu_payload):
    global _coap_msg_id
    _coap_msg_id += 1
    buf = bytearray()
    buf.append(0x42)
    buf.append(0x02)
    buf.extend(struct.pack("!H", _coap_msg_id))
    buf.extend(struct.pack("!H", _coap_msg_id))
    buf.append(0xB7)
    buf.extend(b"nlltpdu")
    buf.append(0xFF)
    buf.extend(ltpdu_payload)
    return bytes(buf)


def _parse_ble_ltpdu_response(data):
    offset = 0
    endpoint = ""
    status = -1
    value = b""
    while offset + 4 <= len(data):
        tag = struct.unpack_from("!H", data, offset)[0]
        length = struct.unpack_from("!H", data, offset + 2)[0]
        v = data[offset + 4 : offset + 4 + length]
        if tag == 1:
            endpoint = v.decode("utf-8", errors="replace")
        elif tag == 3:
            if len(v) >= 1:
                status = v[0]
                value = v[1:]
        elif tag == 2:
            value = v
        offset += 4 + length
    return endpoint, status, value


async def scan_sense_switches(timeout=15.0):
    """Scan for nearby Sense+ switches advertising over BLE."""
    try:
        from bleak import BleakScanner
    except ImportError:
        print("  ERROR: bleak not installed. Run: pip install bleak")
        return []

    # Patch bleak CoreBluetooth descriptor discovery (macOS)
    try:
        import bleak.backends.corebluetooth.PeripheralDelegate as _pd
        _orig = _pd.PeripheralDelegate.discover_descriptors
        async def _patched(self, char):
            try:
                return await _orig(self, char)
            except Exception:
                return []
        _pd.PeripheralDelegate.discover_descriptors = _patched
    except (ImportError, AttributeError):
        pass

    print(f"\nScanning for Sense+ switches ({int(timeout)}s)...")
    print("TIP: Hold the ON and OFF buttons on the switch for 3 seconds")
    print("     until the white LED flashes to start BLE advertising.\n")

    discovered = await BleakScanner.discover(timeout=timeout, return_adv=True)

    switches = []
    for address, (device, adv) in discovered.items():
        name = device.name or adv.local_name or ""
        if "wireless sw" in name.lower() or "sense" in name.lower():
            switches.append((name, device.address, adv.rssi))

    if switches:
        print(f"Found {len(switches)} Sense+ switch(es):")
        print(f"{'Name':<35} {'Address':<38} {'RSSI'}")
        print("─" * 80)
        for name, addr, rssi in switches:
            print(f"{name:<35} {addr:<38} {rssi} dBm")
        print()
    else:
        print("No Sense+ switches found.")
        print("Make sure you held the ON + OFF buttons for 3s until the white light flashed.\n")

    return switches


async def write_shared_secret_ble(switch_name, setup_code, shared_secret):
    """Write sp/ss to the Sense+ switch via BLE. Returns True on success."""
    try:
        from bleak import BleakClient, BleakScanner
    except ImportError:
        print("  ERROR: bleak not installed. Run: pip install bleak")
        return False

    # Patch bleak CoreBluetooth descriptor discovery (macOS)
    try:
        import bleak.backends.corebluetooth.PeripheralDelegate as _pd
        _orig = _pd.PeripheralDelegate.discover_descriptors
        async def _patched(self, char):
            try:
                return await _orig(self, char)
            except Exception:
                return []
        _pd.PeripheralDelegate.discover_descriptors = _patched
    except (ImportError, AttributeError):
        pass

    print(f"\n  Scanning for '{switch_name}'...")
    print("  (Hold ON + OFF buttons on switch for 3s until white light flashes)")
    device = await BleakScanner.find_device_by_name(switch_name, timeout=20)
    if not device:
        print("  ERROR: Switch not found. Make sure:")
        print("    - The switch name is correct")
        print("    - You pressed a button within the last 30 seconds")
        return False

    print(f"  Found: {device.address}")

    async with BleakClient(device, timeout=20) as client:
        session = LegacyBleSession(client)

        # Key exchange
        print("  Key exchange...")
        await session.key_exchange()
        session._init_ciphers(session._shared_secret, use_new_salts=True)

        # Pair with setup code
        print("  Pairing...")
        code_bytes = setup_code.replace("-", "").encode()
        tlv_pairing = bytes([0x03, len(code_bytes)]) + code_bytes
        resp = await session.send_encrypted_setup(tlv_pairing)
        if len(resp) == 1 and resp[0] != 0:
            print(f"  ERROR: Pairing failed (code 0x{resp[0]:02X})")
            return False
        print("  Paired OK")

        # Write sp/ss
        print(f"  Writing sp/ss ({len(shared_secret)} bytes)...")
        ltpdu_cmd = _build_ble_ltpdu_cmd("sp/ss", shared_secret, method=1)
        coap_frame = _wrap_coap(ltpdu_cmd)
        resp = await session.send_encrypted(coap_frame)

        # Verify by reading back
        print("  Verifying...")
        get_cmd = _build_ble_ltpdu_cmd("sp/ss", method=0)
        coap_get = _wrap_coap(get_cmd)
        resp = await session.send_encrypted(coap_get)
        if len(resp) > 4:
            ff_idx = resp.find(0xFF)
            if ff_idx >= 0:
                ltpdu_resp = resp[ff_idx + 1 :]
                try:
                    ep, status, val = _parse_ble_ltpdu_response(ltpdu_resp)
                    if val == shared_secret:
                        print("  Verified: sp/ss matches!")
                        return True
                    else:
                        print("  WARNING: readback mismatch")
                        return False
                except Exception:
                    pass

        # Couldn't verify but write may have succeeded
        print("  Write sent (could not verify readback)")
        return True


# ---------------------------------------------------------------------------
# Serial port & Firmware detection
# ---------------------------------------------------------------------------

SYNC_BYTE = 0xAA
LITEWAVE_PAN = 0x3B71
LITEWAVE_DST = 0xFFF0


def list_candidate_serial_ports():
    """List likely ESP32 serial ports, filtering out Bluetooth/virtual ports."""
    try:
        import serial.tools.list_ports
        comports = serial.tools.list_ports.comports()
        candidates = []
        for p in comports:
            dev = p.device
            desc = p.description or ""
            # Filter obvious non-USB / virtual ports
            if "bluetooth" in dev.lower() or "debug-console" in dev.lower():
                continue
            candidates.append(p)
        return candidates
    except Exception:
        # Fallback to glob
        paths = (
            glob.glob("/dev/cu.usbmodem*")
            + glob.glob("/dev/cu.usbserial*")
            + glob.glob("/dev/ttyACM*")
            + glob.glob("/dev/ttyUSB*")
        )
        return [type("Port", (), {"device": p, "description": "Serial Port", "hwid": ""})() for p in paths]


def select_serial_port(explicit_port=None):
    """
    Select serial port: if explicitly provided, return it.
    If multiple found, prompt the user to choose.
    """
    if explicit_port:
        return explicit_port

    candidates = list_candidate_serial_ports()
    if not candidates:
        return None

    if len(candidates) == 1:
        chosen = candidates[0].device
        print(f"  Auto-selected serial port: {chosen} ({candidates[0].description})")
        return chosen

    print("\n  Multiple serial ports detected:")
    for idx, p in enumerate(candidates, 1):
        desc = p.description if p.description and p.description != "n/a" else ""
        print(f"    [{idx}] {p.device}  {desc}")

    while True:
        try:
            choice = input(f"  Please select a port [1-{len(candidates)}]: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(candidates):
                return candidates[int(choice) - 1].device
            # Allow typing port name directly
            for p in candidates:
                if choice == p.device:
                    return p.device
            print(f"  Invalid choice. Enter a number between 1 and {len(candidates)}.")
        except (KeyboardInterrupt, EOFError):
            print("\n  Aborted.")
            sys.exit(1)


def find_serial_port():
    return select_serial_port(None)


def detect_firmware(ser):
    """
    Probe the serial port to identify the firmware running on the ESP32.
    Returns: ('transmitter', info), ('sniffer', info), ('esphome_or_idf', info), or ('unknown', None)
    """
    ser.reset_input_buffer()

    # 1. Probe for Transmitter (0xBB with bad params)
    ser.write(b"\xBB\x00\x00\x00\x00\x00")
    ser.flush()
    time.sleep(0.15)
    resp = ser.read(1024)

    if b"ERR:BAD_PARAMS" in resp or b"LITEWAVE_TX_READY" in resp:
        return "transmitter", "Litewave Transmitter"

    # 2. Probe for Sniffer (send 0xAA probe byte to trigger heartbeat)
    ser.write(b"\xAA")
    ser.flush()

    start = time.time()
    buf = bytearray()
    while time.time() - start < 1.2:
        b = ser.read(ser.in_waiting or 1)
        if b:
            buf.extend(b)
            # Look for 0xAA sync byte in buffer
            idx = buf.find(SYNC_BYTE)
            if idx >= 0 and len(buf) >= idx + 2:
                total_len = buf[idx + 1]
                if len(buf) >= idx + 2 + total_len:
                    pkt = buf[idx : idx + 2 + total_len]
                    # Verify checksum
                    chk = total_len
                    for byte in pkt[2:]:
                        chk ^= byte
                    if (chk & 0xFF) == 0:
                        ch = pkt[2]
                        if ch == 0 and b"LWSNIFF" in pkt:
                            channel_locked = pkt[3]
                            return "sniffer", f"channel {channel_locked}"
                        elif ch >= 11 and ch <= 26:
                            return "sniffer", f"active frames on ch {ch}"
        time.sleep(0.05)

    try:
        text = buf.decode("utf-8", errors="ignore")
        if any(marker in text for marker in ["[I][", "[D][", "[E][", "[W][", "ESP-ROM", "rst:", "boot:"]):
            return "esphome_or_idf", "ESPHome / custom firmware"
    except Exception:
        pass

    return "unknown", None


def flash_firmware(port, fw_type="sniffer", baud=460800):
    """Flash pre-built firmware (sniffer or transmitter) to the ESP32-C6."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    fw_dir = os.path.join(base_dir, "firmware", fw_type)

    bootloader = os.path.join(fw_dir, "bootloader.bin")
    partition_table = os.path.join(fw_dir, "partition-table.bin")
    app_bin_name = "litewave_sniffer.bin" if fw_type == "sniffer" else "litewave_tx.bin"
    app_bin = os.path.join(fw_dir, app_bin_name)

    for f in [bootloader, partition_table, app_bin]:
        if not os.path.exists(f):
            print(f"  ERROR: Firmware file not found: {f}")
            return False

    print(f"\n  Flashing {fw_type} firmware to {port} @ {baud}...")
    cmd = [
        sys.executable,
        "-m",
        "esptool",
        "--chip",
        "esp32c6",
        "-p",
        port,
        "-b",
        str(baud),
        "--before",
        "default_reset",
        "--after",
        "hard_reset",
        "write_flash",
        "--flash_mode",
        "dio",
        "--flash_freq",
        "80m",
        "--flash_size",
        "2MB",
        "0x0",
        bootloader,
        "0x8000",
        partition_table,
        "0x10000",
        app_bin,
    ]

    try:
        import subprocess
        res = subprocess.run(cmd)
        if res.returncode == 0:
            print(f"\n  ✓ Successfully flashed {fw_type} firmware!")
            time.sleep(1.5)  # Allow USB serial to re-enumerate
            return True
        else:
            print(f"\n  ❌ Flashing failed with exit code {res.returncode}")
            return False
    except Exception as e:
        print(f"\n  ❌ Failed to run esptool: {e}")
        return False


def verify_sniffer_firmware(ser, port, auto_flash=False):
    """
    Check if the sniffer firmware is running on the device.
    Offers or handles automatic flashing if transmitter or other firmware is found.
    Returns (ok_bool, ser_handle).
    """
    fw, info = detect_firmware(ser)
    if fw == "sniffer":
        detail = f" ({info})" if info else ""
        print(f"  ✓ Confirmed sniffer firmware on {port}{detail}")
        return True, ser

    if fw == "transmitter":
        print(f"\n  ❌ FIRMWARE MISMATCH on {port}:")
        print("     The device is running the Litewave TRANSMITTER firmware (litewave_tx)!")
        print("     Capture requires the Litewave SNIFFER firmware (litewave_sniffer).\n")
    elif fw == "esphome_or_idf":
        print(f"\n  ⚠️  FIRMWARE NOTICE on {port}:")
        print("     The device appears to be running ESPHome / custom firmware, not the raw sniffer.\n")
    else:
        print(f"\n  ℹ Port {port} did not respond to sniffer probe.\n")

    if auto_flash:
        print("  Auto-flashing sniffer firmware...")
        ser.close()
        if flash_firmware(port, "sniffer"):
            new_ser = serial.Serial(port, 115200, timeout=0.1)
            time.sleep(0.5)
            new_ser.reset_input_buffer()
            return True, new_ser
        return False, None

    # Interactive offer to flash
    try:
        ans = input("  Would you like to flash the sniffer firmware now? [Y/n]: ").strip().lower()
        if ans in ("", "y", "yes"):
            ser.close()
            if flash_firmware(port, "sniffer"):
                new_ser = serial.Serial(port, 115200, timeout=0.1)
                time.sleep(0.5)
                new_ser.reset_input_buffer()
                return True, new_ser
            return False, None
    except (KeyboardInterrupt, EOFError):
        print("\n  Aborted.")

    return False, ser


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

    # Ignore non-radio heartbeat frames (channel == 0)
    if channel == 0:
        return None

    return channel, rssi, lqi, frame_data


def parse_litewave_frame(frame_data):
    """Parse 802.15.4 frame and extract Litewave (dsn, token_hex) or None."""
    if len(frame_data) < 10:
        return None

    fcf = struct.unpack_from("<H", frame_data, 0)[0]
    frame_type = fcf & 0x07
    if frame_type != 1:
        return None

    dsn = frame_data[2]

    dst_mode = (fcf >> 10) & 0x03
    src_mode = (fcf >> 14) & 0x03
    pan_compress = (fcf >> 6) & 0x01

    offset = 3

    if dst_mode == 2:
        if offset + 4 > len(frame_data):
            return None
        dst_pan = struct.unpack_from("<H", frame_data, offset)[0]
        offset += 2
        dst_addr = struct.unpack_from("<H", frame_data, offset)[0]
        offset += 2
    elif dst_mode == 3:
        if offset + 10 > len(frame_data):
            return None
        dst_pan = struct.unpack_from("<H", frame_data, offset)[0]
        offset += 2
        offset += 8
    else:
        return None

    if dst_pan != LITEWAVE_PAN:
        return None
    if dst_mode == 2 and dst_addr != LITEWAVE_DST:
        return None

    if src_mode == 2:
        if not pan_compress:
            offset += 2
        offset += 2
    elif src_mode == 3:
        if not pan_compress:
            offset += 2
        offset += 8

    payload = frame_data[offset:]
    if len(payload) < 16:
        return None

    cmd_type = payload[1]
    token = payload[2:16]

    if cmd_type != 0x00:
        return None

    return dsn, token.hex().upper()


def capture_command(ser, label, timeout=30, debug=False):
    """Wait for a Litewave command burst, return (seq, token_hex) or None."""
    print(f"\n  Listening for {label} command...")
    print(f"  >>> Press the {label} button on the Sense+ switch now <<<")

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
            print(
                f"    frame #{frame_count}: ch={channel} rssi={rssi} "
                f"len={len(frame_data)} hex={frame_data.hex()}"
            )

        result = parse_litewave_frame(frame_data)
        if result is None:
            continue

        seq, token_hex = result
        if captured is None:
            captured = (seq, token_hex)
            print(f"  Captured! seq=0x{seq:02X} token={token_hex} (RSSI={rssi})")
            quiet_since = time.time()
        else:
            quiet_since = time.time()

    if captured:
        time.sleep(1.5)
        ser.reset_input_buffer()

    if not captured:
        print(
            f"  (no Litewave frames captured — {frame_count} raw frames seen)"
        )

    return captured


def parse_and_pad_secret(secret_str: str) -> bytes:
    """Parse a hex string into a 54-byte shared secret, left-padding with zeros if shorter."""
    s = secret_str.strip().replace(" ", "").replace(":", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) > 108:
        raise ValueError(f"Shared secret too long ({len(s)} hex chars, max 108)")
    s = s.rjust(108, "0")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise ValueError(f"Invalid hexadecimal in shared secret: {e}") from e


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

BUTTONS = [
    ("on", "ON"),
    ("off", "OFF"),
    ("dim_plus", "DIM+ (brightness up)"),
    ("dim_minus", "DIM- (brightness down)"),
]


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--flash-sniffer",
        action="store_true",
        help="Flash the pre-built Litewave Sniffer firmware to the ESP32 and exit",
    )
    parser.add_argument(
        "--flash-transmitter",
        action="store_true",
        help="Flash the pre-built Litewave Transmitter firmware to the ESP32 and exit",
    )
    parser.add_argument(
        "--auto-flash",
        action="store_true",
        help="Automatically flash the sniffer firmware if not detected (without prompting)",
    )
    parser.add_argument(
        "--scan-switches",
        action="store_true",
        help="Scan and list nearby Sense+ switches advertising over BLE, then exit",
    )
    parser.add_argument(
        "--switch-name",
        help="BLE device name of the Sense+ switch (e.g. 'Nanoleaf Wireless SW 1D9')",
    )
    parser.add_argument(
        "--switch-code",
        help="Setup code on the back of the switch (e.g. '0242-362-0007')",
    )
    parser.add_argument(
        "--secret",
        help="Shared secret as hex string (auto zero-padded to 54 bytes if shorter, random if omitted)",
    )
    parser.add_argument(
        "--capture-only",
        action="store_true",
        help="Skip BLE write, only capture tokens (secret already on switch)",
    )
    parser.add_argument(
        "--skip-dim",
        action="store_true",
        help="Only capture ON and OFF (skip dim+ and dim-)",
    )
    parser.add_argument(
        "--group-name",
        default="room",
        help="ESPHome group name (default: room)",
    )
    parser.add_argument("--port", help="Sniffer serial port (auto-detected or interactive selection)")
    parser.add_argument(
        "--baud", type=int, default=115200, help="Baud rate (default 115200)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Proceed even if firmware check detects a mismatch",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Show all received frames"
    )
    parser.add_argument(
        "--output", help="Output YAML file (default: captured_<group>.yaml)"
    )
    args = parser.parse_args()

    if args.flash_sniffer or args.flash_transmitter:
        target_fw = "sniffer" if args.flash_sniffer else "transmitter"
        port = select_serial_port(args.port)
        if not port:
            print(f"  No serial port found to flash {target_fw} firmware.")
            sys.exit(1)
        ok = flash_firmware(port, target_fw)
        sys.exit(0 if ok else 1)

    if args.scan_switches:
        asyncio.run(scan_sense_switches(timeout=15.0))
        return

    if not args.capture_only and (not args.switch_name or not args.switch_code):
        parser.error(
            "--switch-name and --switch-code are required (or use --capture-only, --scan-switches, or --flash-sniffer)"
        )

    # Determine shared secret
    if args.secret:
        try:
            secret_bytes = parse_and_pad_secret(args.secret)
        except ValueError as e:
            print(f"ERROR: {e}")
            sys.exit(1)
    elif not args.capture_only:
        secret_bytes = os.urandom(54)
        print(f"Generated random shared secret: {secret_bytes.hex()}")
    else:
        secret_bytes = None

    print()
    print("=" * 56)
    print("  Litewave Capture & Provisioning Tool")
    print("=" * 56)

    # ── Step 1: BLE write ──────────────────────────────────────────
    if not args.capture_only:
        print(f"\n{'─'*56}")
        print("  Step 1: Write shared secret to Sense+ switch via BLE")
        print(f"{'─'*56}")
        print(f"  Secret: {secret_bytes.hex()}")

        ok = asyncio.run(
            write_shared_secret_ble(
                args.switch_name, args.switch_code, secret_bytes
            )
        )
        if not ok:
            print("\n  BLE write failed. Aborting.")
            sys.exit(1)

        print("\n  Secret written successfully.")
        print("  The switch will now generate tokens using this secret.")
    else:
        print("\n  (Skipping BLE write — capture only mode)")

    # ── Step 2: Open sniffer ───────────────────────────────────────
    port = select_serial_port(args.port)
    if not port:
        print(
            "\n  No serial port found. Connect the ESP32-C6 sniffer and "
            "try again,\n  or specify with --port /dev/cu.usbmodemXXXX"
        )
        sys.exit(1)

    print(f"\n  Opening sniffer: {port} @ {args.baud}")

    try:
        ser = serial.Serial(port, args.baud, timeout=0.1)
    except serial.SerialException as e:
        print(f"\n  Could not open {port}: {e}")
        sys.exit(1)

    time.sleep(0.5)
    ser.reset_input_buffer()

    # Firmware check
    ok, ser = verify_sniffer_firmware(ser, port, auto_flash=args.auto_flash)
    if not ok:
        if not args.force:
            if ser:
                ser.close()
            sys.exit(1)
        else:
            print("  (--force specified, continuing anyway)")

    # ── Step 3: Capture buttons ────────────────────────────────────
    buttons_to_capture = BUTTONS if not args.skip_dim else BUTTONS[:2]
    results = {}

    for i, (key, label) in enumerate(buttons_to_capture, 1):
        print(f"\n{'─'*56}")
        print(f"  Step {i + (0 if args.capture_only else 1)}: Capture {label}")
        print(f"{'─'*56}")

        result = capture_command(ser, label, debug=args.debug)
        if result is None:
            if key in ("dim_plus", "dim_minus"):
                print(f"\n  No {label} token captured. Skipping.")
                print(
                    "  (Dim buttons may use a different frame structure — "
                    "run with --debug to investigate)"
                )
                continue
            else:
                print(f"\n  Timeout waiting for {label} command.")
                ser.close()
                sys.exit(1)

        results[key] = result

    ser.close()

    # ── Step 4: Output ─────────────────────────────────────────────
    print(f"\n{'━'*56}")
    print("  Capture complete!")
    print(f"{'━'*56}")

    for key, label in BUTTONS:
        if key in results:
            seq, tok = results[key]
            print(f"  {label:20s}  seq=0x{seq:02X}  token={tok}")

    # Build YAML
    group_name = args.group_name
    lines = [
        "# ESPHome Litewave group config",
        "litewave:",
        "  groups:",
        f"    - id: {group_name}",
    ]
    if secret_bytes:
        if args.secret:
            user_ss = args.secret.strip().replace(" ", "").replace(":", "")
            if not user_ss.lower().startswith("0x") and len(user_ss) < 108:
                ss_yaml = f"0x{user_ss.lower()}"
            else:
                ss_yaml = user_ss.lower()
        else:
            stripped = secret_bytes.hex().lstrip("0")
            if len(stripped) <= 8:
                ss_yaml = f"0x{stripped or '0'}"
            else:
                ss_yaml = secret_bytes.hex()
        lines.append(f'      shared_secret: "{ss_yaml}"')

    for key, label in BUTTONS:
        if key in results:
            seq, tok = results[key]
            lines.append(f"      {key}_sequence: 0x{seq:02X}")
            lines.append(f'      {key}_token: "{tok}"')

    yaml_block = "\n".join(lines) + "\n"

    print(f"\n{'━'*56}")
    print(yaml_block)
    print(f"{'━'*56}")

    outfile = args.output or f"captured_{group_name}.yaml"
    with open(outfile, "w") as f:
        f.write(yaml_block)
    print(f"\n  Saved to {outfile}")

    # Also output JSON for catalog use
    json_data = {"group_name": group_name}
    if secret_bytes:
        json_data["shared_secret"] = secret_bytes.hex()
    for key, _ in BUTTONS:
        if key in results:
            seq, tok = results[key]
            json_data[f"{key}_sequence"] = seq
            json_data[f"{key}_token"] = tok

    return json_data


if __name__ == "__main__":
    main()
