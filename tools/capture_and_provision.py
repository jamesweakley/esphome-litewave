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
        self.cipher_stream = None
        self._shared_secret = None
        self.rx_queue = asyncio.Queue()

    def _init_ciphers(self, shared_secret, use_new_salts=True):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        salt_key = SALT_KEY_NEW if use_new_salts else b"AES-NL-OPENAPI-KEY"
        salt_iv = SALT_IV_NEW if use_new_salts else b"AES-NL-OPENAPI-IV"
        key = hashlib.sha1(salt_key + shared_secret).digest()[:16]
        iv = hashlib.sha1(salt_iv + shared_secret).digest()[:16]
        # Single AES-CTR keystream shared across both TX and RX
        self.cipher_stream = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

    def encrypt(self, data):
        return self.cipher_stream.update(data)

    def decrypt(self, data):
        return self.cipher_stream.update(data)

    def _on_notify(self, sender, data):
        self.rx_queue.put_nowait(bytes(data))

    async def start_notifications(self):
        try:
            await self.client.start_notify(ENCRYPTED_CHAR, self._on_notify)
        except Exception:
            pass

    async def stop_notifications(self):
        try:
            await self.client.stop_notify(ENCRYPTED_CHAR)
        except Exception:
            pass

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
        await asyncio.sleep(0.3)
        response = await self.client.read_gatt_char(ENCRYPTION_SETUP)
        return self.decrypt(bytes(response))

    async def send_encrypted(self, data):
        encrypted = self.encrypt(data)
        # Drain any older notifications
        while not self.rx_queue.empty():
            self.rx_queue.get_nowait()

        await self.client.write_gatt_char(
            ENCRYPTED_CHAR, encrypted, response=True
        )
        try:
            raw_resp = await asyncio.wait_for(self.rx_queue.get(), timeout=4.0)
            return self.decrypt(raw_resp)
        except (asyncio.TimeoutError, Exception):
            # Fallback to direct read if notification not received
            try:
                response = await self.client.read_gatt_char(ENCRYPTED_CHAR)
                return self.decrypt(bytes(response))
            except Exception:
                return b""


def _build_ble_ltpdu_cmd(endpoint, value=None, method=0):
    buf = bytearray()
    ep_bytes = endpoint.encode("utf-8")
    buf.extend(struct.pack(">HH", 1, len(ep_bytes)))
    buf.extend(ep_bytes)
    buf.extend(struct.pack(">HH", 4, 1))
    buf.append(method)  # 0=GET, 1=POST
    if value:
        buf.extend(struct.pack(">HH", 2, len(value)))
        buf.extend(value)
    return bytes(buf)


def _parse_ble_ltpdu_response(data):
    offset = 0
    endpoint = ""
    status = -1
    value = b""
    while offset + 4 <= len(data):
        tag, length = struct.unpack(">HH", data[offset : offset + 4])
        offset += 4
        if offset + length > len(data):
            break
        v = data[offset : offset + length]
        if tag == 1:
            endpoint = v.decode("utf-8", errors="replace")
        elif tag == 3:
            if len(v) >= 1:
                status = v[0]
                value = v[1:]
        elif tag == 2:
            value = v
        offset += length
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


def _handle_ble_error(e: Exception, stage: str = "BLE operation"):
    """Format and display user-friendly explanations for known BLE / GATT errors."""
    err_str = str(e)
    is_err_81 = "0x81" in err_str or " 129," in err_str or "(129" in err_str
    is_err_87 = "0x87" in err_str or " 135," in err_str or "(135" in err_str
    is_err_86 = "0x86" in err_str or " 134," in err_str or "(134" in err_str

    print(f"\n  ❌ {stage} failed with error: {e}")
    if is_err_81:
        print("\n  💡 Root Cause: GATT Error 0x81 (Already Paired / Invalid Pairing Method)")
        print("     The switch is already added/paired in the Nanoleaf app and rejected the Matter setup code.")
        print("     Once paired, the switch only accepts its 16-hex Nanoleaf Cloud Auth Token for BLE session auth.")
        print("\n  👉 How to fix:")
        print("     1. Run: python3 tools/nanoleaf_cloud.py")
        print("     2. Copy the switch's 16-hex Auth Token (e.g. '71a8489c673d929f')")
        print("     3. Re-run this command passing the token:")
        print("        python3 tools/capture_and_provision.py --switch-name \"...\" --switch-code \"<16_HEX_AUTH_TOKEN>\" ...")
    elif is_err_87:
        print("\n  💡 Root Cause: GATT Error 0x87 (Uncommissioned / Security Error)")
        print("     The switch is in a factory-reset / uncommissioned state and cannot accept custom GATT writes.")
        print("\n  👉 How to fix:")
        print("     1. Add the switch to your home in the Nanoleaf app first.")
        print("     2. Retrieve its 16-hex Auth Token by running: python3 tools/nanoleaf_cloud.py")
        print("     3. Re-run this command with the Auth Token via --switch-code <AUTH_TOKEN>")
    elif is_err_86:
        print("\n  💡 Root Cause: GATT Error 0x86 (Invalid Credentials)")
        print("     The switch rejected the provided setup code or Auth Token.")
        print("     Double check the 11-digit code on the back sticker or run 'python3 tools/nanoleaf_cloud.py'.")
    else:
        print("\n  💡 Bluetooth Troubleshooting Tip:")
        print("     - On macOS, CoreBluetooth may cache stale peripheral state. Try running: sudo pkill bluetoothd")
        print("     - Ensure the switch is actively advertising by holding ON + OFF for 3 seconds until the white LED flashes.")


async def write_shared_secret_ble(switch_name, setup_code, shared_secret, pan_id_hex, admin_key_hex, channel_val):
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
    try:
        device = await BleakScanner.find_device_by_name(switch_name, timeout=20)
    except Exception as e:
        _handle_ble_error(e, "BLE device scan")
        return False

    if not device:
        print("  ERROR: Switch not found. Make sure:")
        print("    - The switch name is correct")
        print("    - You pressed a button within the last 30 seconds")
        return False

    print(f"  Found: {device.address}")

    # Prepare radio parameters
    pan_clean = pan_id_hex.replace("0x", "").strip().rjust(4, "0")
    admin_clean = admin_key_hex.replace("0x", "").strip().rjust(4, "0")
    pan_bytes = bytes.fromhex(pan_clean)
    admin_bytes = bytes.fromhex(admin_clean)

    try:
        async with BleakClient(device, timeout=20) as client:
            session = LegacyBleSession(client)

            # Key exchange
            print("  Key exchange...")
            try:
                await session.key_exchange()
            except Exception as e:
                _handle_ble_error(e, "Key exchange")
                return False

            session._init_ciphers(session._shared_secret, use_new_salts=True)

            # Pair with setup code or auth token
            print("  Pairing...")
            clean_code = setup_code.replace("-", "").strip()
            is_token = len(clean_code) == 16 and all(c in "0123456789abcdefABCDEF" for c in clean_code)
            if is_token:
                auth_bytes = bytes.fromhex(clean_code)
                tlv_pairing = bytes([0x02, len(auth_bytes)]) + auth_bytes
            else:
                code_bytes = clean_code.encode("ascii")
                tlv_pairing = bytes([0x03, len(code_bytes)]) + code_bytes

            try:
                resp = await session.send_encrypted_setup(tlv_pairing)
            except Exception as e:
                _handle_ble_error(e, "Pairing / Setup authentication")
                return False

            if len(resp) == 1 and resp[0] != 0:
                err_byte = resp[0]
                if err_byte == 0x86:
                    print(f"  ERROR: Pairing failed (code 0x86 — Invalid credentials).")
                    print(f"         Check the 11-digit Matter setup code on the back sticker of the switch,")
                    print(f"         or supply the switch's 16-hex Nanoleaf Cloud auth token via --switch-token.")
                elif err_byte == 0x81:
                    print(f"  ERROR: Pairing failed (code 0x81 — Already Paired).")
                    print(f"         The switch is paired in the Nanoleaf app and requires its 16-hex Cloud Auth Token.")
                    print(f"         Run 'python3 tools/nanoleaf_cloud.py' to find its Auth Token.")
                elif err_byte == 0x87:
                    print(f"  ERROR: Pairing failed (code 0x87 — Uncommissioned).")
                    print(f"         The switch is uncommissioned. Add it to the Nanoleaf app first.")
                else:
                    print(f"  ERROR: Pairing failed (code 0x{err_byte:02X})")
                return False
            print("  Paired OK")
            await session.start_notifications()
            await asyncio.sleep(0.1)

            # 1. Write sp/admin
            print(f"  Setting switch Admin Key (0x{admin_clean})...")
            resp = await session.send_encrypted(_build_ble_ltpdu_cmd("sp/admin", admin_bytes, method=1))

            # 2. Write sp/pi (PAN ID)
            print(f"  Setting switch PAN ID (0x{pan_clean})...")
            resp = await session.send_encrypted(_build_ble_ltpdu_cmd("sp/pi", pan_bytes, method=1))

            # 3. Write sp/mc (Channel)
            print(f"  Setting switch Channel ({channel_val})...")
            resp = await session.send_encrypted(_build_ble_ltpdu_cmd("sp/mc", bytes([channel_val]), method=1))

            # 4. Write sp/ss (Shared Secret)
            print(f"  Writing switch sp/ss ({len(shared_secret)} bytes)...")
            ltpdu_cmd = _build_ble_ltpdu_cmd("sp/ss", shared_secret, method=1)
            resp = await session.send_encrypted(ltpdu_cmd)
            if resp:
                ep, status, val = _parse_ble_ltpdu_response(resp)
                if status != -1 and status != 0:
                    print(f"  ❌ Switch rejected write: status {status}")
                    return False

            # Verify by reading back
            print("  Verifying switch configuration...")
            get_admin = _build_ble_ltpdu_cmd("sp/admin", method=0)
            resp_admin = await session.send_encrypted(get_admin)
            if resp_admin:
                _, _, val_admin = _parse_ble_ltpdu_response(resp_admin)
                print(f"  -> sp/admin: 0x{val_admin.hex() if val_admin else '?'}")

            get_pi = _build_ble_ltpdu_cmd("sp/pi", method=0)
            resp_pi = await session.send_encrypted(get_pi)
            if resp_pi:
                _, _, val_pi = _parse_ble_ltpdu_response(resp_pi)
                print(f"  -> sp/pi:    0x{val_pi.hex() if val_pi else '?'}")

            get_mc = _build_ble_ltpdu_cmd("sp/mc", method=0)
            resp_mc = await session.send_encrypted(get_mc)
            if resp_mc:
                _, _, val_mc = _parse_ble_ltpdu_response(resp_mc)
                ch_num = val_mc[0] if val_mc else '?'
                print(f"  -> sp/mc:    {ch_num}")

            get_cmd = _build_ble_ltpdu_cmd("sp/ss", method=0)
            resp = await session.send_encrypted(get_cmd)
            if resp:
                ep, status, val = _parse_ble_ltpdu_response(resp)
                if val == shared_secret:
                    print(f"  ✓ Verified: Switch sp/ss matches ({len(val)} bytes)!")
                    return True
                elif val:
                    print(f"  ❌ WARNING: Switch sp/ss mismatch (expected {len(shared_secret)}B, readback {len(val)}B: {val.hex()[:32]}...)")
                    return False
                else:
                    print(f"  Received response ({len(resp)}B): {resp.hex()[:32]}...")

            print("  ⚠️  Write sent but could not verify readback from switch.")
            return True
    except Exception as e:
        _handle_ble_error(e, "BLE session")
        return False


# ---------------------------------------------------------------------------
# Serial port & Firmware detection
# ---------------------------------------------------------------------------

SYNC_BYTE = 0xAA
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


def parse_litewave_frame(frame_data, target_pan=None):
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

    if target_pan is not None and dst_pan != target_pan:
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

    return dsn, token.hex().upper()


def capture_command(ser, label, target_pan=None, timeout=30, debug=False):
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

        result = parse_litewave_frame(frame_data, target_pan=target_pan)
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
        help="Nanoleaf account email (to auto-fetch PAN ID, Admin Key, Channel from cloud)",
    )
    parser.add_argument(
        "--cloud-password",
        default=os.environ.get("NANOLEAF_PASSWORD"),
        help="Nanoleaf account password",
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

    if not args.capture_only and (not args.switch_name or (not args.switch_code and not args.switch_token)):
        parser.error(
            "--switch-name and either --switch-code or --switch-token are required (or use --capture-only, --scan-switches, or --flash-sniffer)"
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
    pan_id_hex = args.pan_id
    admin_key_hex = args.admin_key
    channel_val = args.channel

    if not args.capture_only:
        # Resolve PAN ID, Admin Key, and Channel
        if not pan_id_hex or not admin_key_hex or channel_val is None:
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
                except Exception:
                    pass

        if not pan_id_hex:
            pan_id_hex = input("Enter Nanoleaf Home PAN ID (hex, e.g. from Nanoleaf app/cloud): ").strip()
        if not admin_key_hex:
            admin_key_hex = input("Enter Nanoleaf Home Admin Key (hex): ").strip()
        if channel_val is None:
            ch_in = input("Enter 802.15.4 channel (11-26, default 26): ").strip()
            channel_val = int(ch_in) if ch_in else 26

        print(f"\n{'─'*56}")
        print("  Step 1: Write shared secret to Sense+ switch via BLE")
        print(f"{'─'*56}")
        print(f"  Secret:    {secret_bytes.hex()}")
        print(f"  PAN ID:    0x{pan_id_hex}")
        print(f"  Admin Key: 0x{admin_key_hex}")
        print(f"  Channel:   {channel_val}")

        auth_val = args.switch_token if args.switch_token else args.switch_code
        ok = asyncio.run(
            write_shared_secret_ble(
                args.switch_name, auth_val, secret_bytes, pan_id_hex, admin_key_hex, channel_val
            )
        )
        if not ok:
            print("\n  BLE write failed. Aborting.")
            sys.exit(1)

        print("\n  Secret written successfully.")
        print("  The switch will now generate tokens using this secret.")
    else:
        print("\n  (Skipping BLE write — capture only mode)")

    target_pan_uint = int(pan_id_hex.replace("0x", ""), 16) if pan_id_hex else None

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

        result = capture_command(ser, label, target_pan=target_pan_uint, debug=args.debug)
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
