#!/usr/bin/env python3
"""
Authenticated BLE session with Nanoleaf Sense+ switch.
Reads SensePlus configuration endpoints via encrypted LTPDU.
Usage: python3 ble_sense_ltpdu.py <auth_token_hex>
"""

import asyncio
import hashlib
import struct
import sys
from bleak import BleakScanner
from bleak.backends.corebluetooth.client import BleakClientCoreBluetooth
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import CoreBluetooth as CB
import objc
from Foundation import NSObject

UUID_UNENCRYPTED = "A9E0A2DE-9AEA-11EA-BB37-0242AC130002"
UUID_ENCRYPTED = "6D2ADDA0-9AEA-11EA-BB37-0242AC130002"
UUID_ENCRYPTION_SETUP = "6D2ADFDA-9AEA-11EA-BB37-0242AC130002"

SALT_NEW = bytes.fromhex("bca9e39738e2611c25d243c985d3c592ccbee330e077b89d7978f5fc785cb5e8")
IV_SALT_NEW = bytes.fromhex("41e2e9eb5e5fa56e800e346d8c2b600742eb49839626faecdc37fb94a3a3c202")

# LTPDU endpoints to probe on the Sense+ switch
ENDPOINTS = [
    "sp/ss",         # SharedSecret (CRITICAL)
    "sp/pi",         # PanId
    "sp/admin",      # SensePlusAdmin
    "sp/mc",         # Thread channel
]


class EncryptedSession:
    def __init__(self):
        self.private_key = None
        self.public_key_bytes = None
        self.shared_secret = None
        self.encrypt_cipher = None
        self.decrypt_cipher = None

    def generate_keypair(self):
        self.private_key = X25519PrivateKey.generate()
        self.public_key_bytes = self.private_key.public_key().public_bytes_raw()
        return self.public_key_bytes

    def compute_shared_secret(self, peer_public_bytes):
        peer_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
        self.shared_secret = self.private_key.exchange(peer_key)

    def initialize_ciphers(self):
        key_material = SALT_NEW + self.shared_secret
        aes_key = hashlib.sha1(key_material).digest()[:16]
        iv_material = IV_SALT_NEW + self.shared_secret
        aes_iv = hashlib.sha1(iv_material).digest()[:16]
        self.encrypt_cipher = Cipher(algorithms.AES(aes_key), modes.CTR(aes_iv)).encryptor()
        self.decrypt_cipher = Cipher(algorithms.AES(aes_key), modes.CTR(aes_iv)).decryptor()

    def encrypt(self, data):
        self.decrypt_cipher.update(data)
        return self.encrypt_cipher.update(data)

    def decrypt(self, data):
        self.encrypt_cipher.update(data)
        return self.decrypt_cipher.update(data)


def build_tlv(tlv_type, data):
    result = bytearray()
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + 255]
        result.append(tlv_type)
        result.append(len(chunk))
        result.extend(chunk)
        offset += len(chunk)
    if not data:
        result.append(tlv_type)
        result.append(0)
    return bytes(result)


def build_ltpdu_get(endpoint):
    """Build LTPDU v2 GET request for an endpoint."""
    buf = bytearray()
    ep_bytes = endpoint.encode("utf-8")
    # Tag 0x0001 = endpoint
    buf.extend(struct.pack(">HH", 1, len(ep_bytes)))
    buf.extend(ep_bytes)
    # Tag 0x0004 = method, len=1, value=0 (GET)
    buf.extend(struct.pack(">HH", 4, 1))
    buf.append(0)  # GET
    return bytes(buf)


def build_ltpdu_post(endpoint, value):
    """Build LTPDU v2 POST request."""
    buf = bytearray()
    ep_bytes = endpoint.encode("utf-8")
    buf.extend(struct.pack(">HH", 1, len(ep_bytes)))
    buf.extend(ep_bytes)
    buf.extend(struct.pack(">HH", 4, 1))
    buf.append(1)  # POST
    buf.extend(struct.pack(">HH", 2, len(value)))
    buf.extend(value)
    return bytes(buf)


def parse_ltpdu_response(data):
    """Parse LTPDU TLV response."""
    entries = []
    offset = 0
    while offset + 4 <= len(data):
        tag, length = struct.unpack(">HH", data[offset:offset+4])
        offset += 4
        if offset + length > len(data):
            entries.append((tag, data[offset:]))
            break
        value = data[offset:offset+length]
        entries.append((tag, value))
        offset += length
    return entries


TAG_NAMES = {
    1: "ENDPOINT",
    2: "VALUE",
    3: "STATUS_VALUE",  # first byte = status, rest = value
    4: "METHOD",
    5: "TOKEN",
}

STATUS_NAMES = {
    0: "SUCCESS",
    1: "UNKNOWN",
    2: "NOT_FOUND",
    3: "BAD_REQUEST",
    4: "UNAUTHORIZED",
    5: "CANNOT_WRITE",
}


class BLEDelegate(NSObject):
    def init(self):
        self = objc.super(BLEDelegate, self).init()
        self.read_results = {}
        self.read_events = {}
        self.write_results = {}
        self.write_events = {}
        self.chars_pending = 0
        self.chars_done = asyncio.Event()
        self.notify_data = {}
        self.notify_events = {}
        return self

    def peripheral_didUpdateValueForCharacteristic_error_(self, peripheral, char, error):
        cuuid = str(char.UUID())
        if error:
            self.read_results[cuuid] = (None, str(error))
        else:
            val = char.value()
            raw = bytes(val) if val else b""
            self.read_results[cuuid] = (raw, None)
        if cuuid in self.read_events:
            self.read_events[cuuid].set()
        # Also fire notify event
        if cuuid in self.notify_events:
            val = char.value()
            self.notify_data[cuuid] = bytes(val) if val else b""
            self.notify_events[cuuid].set()

    def peripheral_didWriteValueForCharacteristic_error_(self, peripheral, char, error):
        cuuid = str(char.UUID())
        self.write_results[cuuid] = str(error) if error else "OK"
        if cuuid in self.write_events:
            self.write_events[cuuid].set()

    def peripheral_didUpdateNotificationStateForCharacteristic_error_(self, peripheral, char, error):
        pass

    def peripheral_didDiscoverServices_(self, peripheral, error):
        services = peripheral.services() or []
        self.chars_pending = len(services)
        if self.chars_pending == 0:
            self.chars_done.set()
        for svc in services:
            peripheral.discoverCharacteristics_forService_(None, svc)

    def peripheral_didDiscoverCharacteristicsForService_error_(self, peripheral, service, error):
        self.chars_pending -= 1
        if self.chars_pending <= 0:
            self.chars_done.set()


async def ble_write(delegate, peripheral, char, data, timeout=5.0):
    cuuid = str(char.UUID())
    evt = asyncio.Event()
    delegate.write_events[cuuid] = evt
    ns_data = CB.NSData.dataWithBytes_length_(data, len(data))
    peripheral.writeValue_forCharacteristic_type_(ns_data, char, 0)
    try:
        await asyncio.wait_for(evt.wait(), timeout=timeout)
        return delegate.write_results.get(cuuid, "?")
    except asyncio.TimeoutError:
        return "timeout"


async def ble_read(delegate, peripheral, char, timeout=5.0):
    cuuid = str(char.UUID())
    evt = asyncio.Event()
    delegate.read_events[cuuid] = evt
    peripheral.readValueForCharacteristic_(char)
    try:
        await asyncio.wait_for(evt.wait(), timeout=timeout)
        return delegate.read_results.get(cuuid, (None, "?"))
    except asyncio.TimeoutError:
        return None, "timeout"


async def wait_notify(delegate, cuuid, timeout=3.0):
    evt = asyncio.Event()
    delegate.notify_events[cuuid] = evt
    try:
        await asyncio.wait_for(evt.wait(), timeout=timeout)
        return delegate.notify_data.get(cuuid)
    except asyncio.TimeoutError:
        return None


def find_char(services, target_uuid):
    target = target_uuid.upper()
    for svc in services:
        for ch in (svc.characteristics() or []):
            if str(ch.UUID()).upper() == target:
                return ch
    return None


async def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ble_sense_ltpdu.py <auth_token_hex>")
        sys.exit(1)

    auth_token = bytes.fromhex(sys.argv[1])
    print(f"Auth token: {auth_token.hex()}")

    print("Scanning for Nanoleaf Wireless SW...")
    for attempt in range(3):
        devices = await BleakScanner.discover(timeout=10.0, return_adv=True)
        target = None
        for addr, (dev, adv) in devices.items():
            name = dev.name or adv.local_name or ""
            if "Wireless SW" in name:
                print(f"Found: {name} RSSI={adv.rssi}")
                target = dev
                break
        if target:
            break
        print(f"  Not found (attempt {attempt+1}/3), retrying...")

    if not target:
        print("Switch not found")
        return

    # Connect (with retry)
    backend = None
    for conn_attempt in range(3):
        try:
            if conn_attempt > 0:
                print(f"  Connect retry {conn_attempt+1}/3 (waiting 3s)...")
                await asyncio.sleep(3.0)
                # Re-scan to get fresh device handle
                devices = await BleakScanner.discover(timeout=5.0, return_adv=True)
                for addr, (dev, adv) in devices.items():
                    name = dev.name or adv.local_name or ""
                    if "Wireless SW" in name:
                        target = dev
                        break
            print(f"Connecting (attempt {conn_attempt+1})...")
            backend = BleakClientCoreBluetooth(target, timeout=10.0)
            async def noop(): pass
            backend._get_services = noop
            await backend.connect(False)
            print("Connected")
            break
        except Exception as e:
            print(f"  Connect failed: {e}")
            backend = None
    
    if not backend or not backend.is_connected:
        print("Could not connect after 3 attempts. Try waiting 60s then pressing the switch button.")
        return

    peripheral = backend._peripheral
    delegate = BLEDelegate.alloc().init()
    peripheral.setDelegate_(delegate)

    peripheral.discoverServices_(None)
    try:
        await asyncio.wait_for(delegate.chars_done.wait(), timeout=10.0)
    except asyncio.TimeoutError:
        print("Discovery timeout")
        await backend.disconnect()
        return

    services = peripheral.services() or []
    ch_setup = find_char(services, UUID_ENCRYPTION_SETUP)
    ch_encrypted = find_char(services, UUID_ENCRYPTED)

    if not ch_setup or not ch_encrypted:
        print("Required characteristics not found")
        await backend.disconnect()
        return

    await asyncio.sleep(0.5)  # Let the connection stabilize

    # Key exchange (single attempt - retrying on same connection doesn't help)
    session = EncryptedSession()
    our_pubkey = session.generate_keypair()
    result = await ble_write(delegate, peripheral, ch_setup, our_pubkey, timeout=8.0)
    if result != "OK":
        print(f"Key write failed: {result}")
        print("  (Try: toggle Bluetooth off/on, or 'sudo pkill bluetoothd', then press switch button)")
        try: await backend.disconnect()
        except: pass
        return

    await asyncio.sleep(0.3)
    peer_pubkey, error = await ble_read(delegate, peripheral, ch_setup)
    if error or not peer_pubkey or len(peer_pubkey) != 32:
        print(f"Peer key read failed: {error}")
        await backend.disconnect()
        return

    session.compute_shared_secret(peer_pubkey)
    session.initialize_ciphers()

    # Authenticate
    tlv_data = build_tlv(0x02, auth_token)  # TLV_SALT
    encrypted_auth = session.encrypt(tlv_data)
    result = await ble_write(delegate, peripheral, ch_setup, encrypted_auth)
    if result != "OK":
        print(f"Auth write failed: {result}")
        await backend.disconnect()
        return

    await asyncio.sleep(0.5)
    response, error = await ble_read(delegate, peripheral, ch_setup)
    if response:
        decrypted = session.decrypt(response)
        print(f"Auth OK: {decrypted.hex()}")
    else:
        print(f"Auth response empty/error: {error}")
        await backend.disconnect()
        return

    # Subscribe to notifications on encrypted characteristic
    peripheral.setNotifyValue_forCharacteristic_(True, ch_encrypted)
    await asyncio.sleep(0.3)

    # Helper to send LTPDU and get parsed response
    async def send_ltpdu(req_bytes, label):
        encrypted_req = session.encrypt(req_bytes)
        cuuid_enc = str(ch_encrypted.UUID())
        delegate.read_events[cuuid_enc] = asyncio.Event()
        
        result = await ble_write(delegate, peripheral, ch_encrypted, encrypted_req)
        if result != "OK":
            print(f"  {label}: write error {result}")
            return None, None
        
        await asyncio.sleep(0.1)
        resp, error = await ble_read(delegate, peripheral, ch_encrypted)
        if not resp:
            print(f"  {label}: no response ({error})")
            return None, None
        
        decrypted = session.decrypt(resp)
        entries = parse_ltpdu_response(decrypted)
        for tag, value in entries:
            if tag == 3:  # STATUS + VALUE
                status = value[0] if value else -1
                payload = value[1:] if len(value) > 1 else b""
                sname = STATUS_NAMES.get(status, f"UNK({status})")
                val_str = f" value={payload.hex()} ({len(payload)}B)" if payload else ""
                print(f"  {label}: {sname}{val_str}")
                return status, payload
        print(f"  {label}: raw={decrypted.hex()}")
        return -1, b""

    # === Phase 1: Read key endpoints ===
    print(f"\n{'='*60}")
    print("Phase 1: Reading endpoints")
    print(f"{'='*60}")

    current_ss = None
    for endpoint in ENDPOINTS:
        status, payload = await send_ltpdu(build_ltpdu_get(endpoint), f"GET {endpoint}")
        if status is None:
            print("  Connection dropped, stopping reads")
            break
        if endpoint == "sp/ss" and status == 0:
            current_ss = payload

    # === Phase 2: Write new shared secret (NO RESTORE) ===
    if current_ss:
        import os
        new_ss = os.urandom(54)
        
        print(f"\n{'='*60}")
        print("Phase 2: Write NEW shared secret (will NOT restore)")
        print(f"{'='*60}")
        print(f"  Original: {current_ss.hex()}")
        print(f"  New:      {new_ss.hex()}")
        
        # Write new secret
        status, payload = await send_ltpdu(build_ltpdu_post("sp/ss", new_ss), "POST sp/ss")
        
        # Verify
        if status == 0:
            status, readback = await send_ltpdu(build_ltpdu_get("sp/ss"), "GET sp/ss (verify)")
            if readback and readback == new_ss:
                print(f"\n  *** Secret changed successfully! ***")
                print(f"  Now press the switch buttons and check if lights respond.")
                print(f"  Original secret (to restore later): {current_ss.hex()}")
            elif readback:
                print(f"\n  Readback mismatch: {readback.hex()}")
        else:
            print(f"\n  Write failed with status {status}")

    try:
        await backend.disconnect()
    except:
        pass
    await asyncio.sleep(0.5)
    print("\nDone")


def run():
    loop = asyncio.new_event_loop()
    loop.set_exception_handler(lambda l, c: None)
    loop.run_until_complete(main())
    loop.close()

run()
