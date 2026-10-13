#!/usr/bin/env python3
"""
Write sp/ss to a Nanoleaf switch via BLE legacy protocol.
Uses Curve25519 key exchange + AES-CTR encryption on service 6d2ae1c4.
After pairing, sends LTPDU TLV commands over the ENCRYPTED characteristic.
"""

import asyncio
import hashlib
import json
import os
import struct
import sys

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

# Patch bleak CoreBluetooth descriptor discovery
import bleak.backends.corebluetooth.PeripheralDelegate as _pd
_orig = _pd.PeripheralDelegate.discover_descriptors
async def _patched(self, char):
    try:
        return await _orig(self, char)
    except Exception:
        return []
_pd.PeripheralDelegate.discover_descriptors = _patched

# GATT UUIDs
ENCRYPTION_SETUP = "6d2adfda-9aea-11ea-bb37-0242ac130002"
ENCRYPTED_CHAR   = "6d2adda0-9aea-11ea-bb37-0242ac130002"

# New salts (Matter/SensePlus devices)
SALT_KEY_NEW = bytes.fromhex("bca9e39738e2611c25d243c985d3c592ccbee330e077b89d7978f5fc785cb5e8")
SALT_IV_NEW  = bytes.fromhex("41e2e9eb5e5fa56e800e346d8c2b600742eb49839626faecdc37fb94a3a3c202")


class LegacyBleSession:
    def __init__(self, client):
        self.client = client
        self.encrypt_cipher = None
        self.decrypt_cipher = None
        self._shared_secret = None

    def _init_ciphers(self, shared_secret, use_new_salts=True):
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
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        print(f"  Our pubkey: {pub.hex()[:16]}...")
        await self.client.write_gatt_char(ENCRYPTION_SETUP, pub, response=True)
        their_pub_raw = await self.client.read_gatt_char(ENCRYPTION_SETUP)
        their_pub_raw = bytes(their_pub_raw)
        print(f"  Their pubkey: {their_pub_raw.hex()[:16]}...")
        their_pub = X25519PublicKey.from_public_bytes(their_pub_raw)
        self._shared_secret = priv.exchange(their_pub)
        print(f"  Shared secret: {self._shared_secret.hex()[:16]}...")
        return True

    async def send_encrypted_setup(self, data):
        encrypted = self.encrypt(data)
        await self.client.write_gatt_char(ENCRYPTION_SETUP, encrypted, response=True)
        response = await self.client.read_gatt_char(ENCRYPTION_SETUP)
        return self.decrypt(bytes(response))

    async def send_encrypted(self, data):
        encrypted = self.encrypt(data)
        await self.client.write_gatt_char(ENCRYPTED_CHAR, encrypted, response=True)
        response = await self.client.read_gatt_char(ENCRYPTED_CHAR)
        return self.decrypt(bytes(response))


def build_ltpdu_cmd(endpoint, value=None, method=0):
    """Build LTPDU TLV: ENDPOINT(1) + PAYLOAD(2) + METHOD(4)"""
    ep = endpoint.encode("utf-8")
    tlv = struct.pack("!HH", 1, len(ep)) + ep
    tlv += struct.pack("!HH", 2, len(value) if value else 0)
    if value:
        tlv += value
    tlv += struct.pack("!HH", 4, 1) + bytes([method])
    return tlv


_coap_msg_id = 0

def wrap_coap(ltpdu_payload):
    """Wrap LTPDU TLV in a CoAP POST to URI 'nlltpdu'."""
    global _coap_msg_id
    _coap_msg_id += 1
    buf = bytearray()
    buf.append(0x42)  # Ver=1, Type=0(CON), TKL=2
    buf.append(0x02)  # Code: POST
    buf.extend(struct.pack('!H', _coap_msg_id))
    buf.extend(struct.pack('!H', _coap_msg_id))  # token = msg_id
    # URI-Path option: delta=11, length=7 ("nlltpdu")
    buf.append(0xB7)  # delta=11, length=7
    buf.extend(b'nlltpdu')
    buf.append(0xFF)  # payload marker
    buf.extend(ltpdu_payload)
    return bytes(buf)


def parse_ltpdu_response(data):
    offset = 0
    endpoint = ""
    status = -1
    value = b""
    while offset + 4 <= len(data):
        tag = struct.unpack_from("!H", data, offset)[0]
        length = struct.unpack_from("!H", data, offset + 2)[0]
        v = data[offset + 4:offset + 4 + length]
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


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "Nanoleaf Wireless SW 1D9"
    setup_code = sys.argv[2] if len(sys.argv) > 2 else "0242-362-0007"

    # Load group B SS
    group_b_ss = bytes.fromhex(json.load(open('/tmp/group_b_ss.json'))['group_b_ss'])
    print(f"Group B SS: {group_b_ss.hex()[:20]}...")

    print(f"\nScanning for '{target}'...")
    device = await BleakScanner.find_device_by_name(target, timeout=15)
    if not device:
        print("Not found! Press button on switch to start BLE advertising.")
        return

    print(f"Found: {device.address}")

    async with BleakClient(device, timeout=20) as client:
        print(f"Connected! MTU={client.mtu_size}")

        session = LegacyBleSession(client)

        # Key exchange
        print("\n=== Key Exchange ===")
        await session.key_exchange()
        session._init_ciphers(session._shared_secret, use_new_salts=True)

        # Pair with setup code
        print("\n=== Pairing ===")
        code_bytes = setup_code.replace("-", "").encode()
        tlv_pairing = bytes([0x03, len(code_bytes)]) + code_bytes
        resp = await session.send_encrypted_setup(tlv_pairing)
        print(f"  Pairing response ({len(resp)}B): {resp.hex()}")
        if len(resp) == 1 and resp[0] != 0:
            print(f"  ERROR: code 0x{resp[0]:02X}")
            return
        print("  Pairing OK!")

        # Try sending LTPDU POST sp/ss via ENCRYPTED characteristic (CoAP wrapped)
        print("\n=== Writing sp/ss via LTPDU (CoAP) ===")
        ltpdu_cmd = build_ltpdu_cmd('sp/ss', group_b_ss, method=1)  # POST
        coap_frame = wrap_coap(ltpdu_cmd)
        print(f"  CoAP frame ({len(coap_frame)}B): {coap_frame.hex()[:40]}...")

        resp = await session.send_encrypted(coap_frame)
        print(f"  Response ({len(resp)}B): {resp.hex()}")

        # Try to parse as CoAP response (skip CoAP header to get LTPDU TLV)
        if len(resp) > 4:
            # Find payload marker 0xFF
            ff_idx = resp.find(0xFF)
            if ff_idx >= 0:
                ltpdu_resp = resp[ff_idx+1:]
                print(f"  LTPDU payload ({len(ltpdu_resp)}B): {ltpdu_resp.hex()}")
                try:
                    ep, status, val = parse_ltpdu_response(ltpdu_resp)
                    print(f"  -> endpoint={ep} status={status}")
                except:
                    pass
            else:
                # Try direct LTPDU parse
                try:
                    ep, status, val = parse_ltpdu_response(resp)
                    print(f"  LTPDU: endpoint={ep} status={status}")
                except:
                    print(f"  (not parseable)")

        # Also try GET sp/ss to verify
        print("\n=== Verifying sp/ss ===")
        get_cmd = build_ltpdu_cmd('sp/ss', method=0)  # GET
        coap_get = wrap_coap(get_cmd)
        resp = await session.send_encrypted(coap_get)
        print(f"  Response ({len(resp)}B): {resp.hex()}")
        if len(resp) > 4:
            ff_idx = resp.find(0xFF)
            if ff_idx >= 0:
                ltpdu_resp = resp[ff_idx+1:]
                try:
                    ep, status, val = parse_ltpdu_response(ltpdu_resp)
                    print(f"  -> endpoint={ep} status={status} val_len={len(val)}")
                    if val:
                        print(f"  -> matches group B: {val == group_b_ss}")
                except:
                    pass


if __name__ == '__main__':
    asyncio.run(main())
