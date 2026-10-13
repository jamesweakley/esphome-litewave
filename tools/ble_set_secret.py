#!/usr/bin/env python3
"""
Write a shared secret to the Nanoleaf Sense+ switch via BLE.
Generates a random 54-byte secret if none provided.

Usage:
  python3 ble_set_secret.py <auth_token_hex> [secret_hex]

Examples:
  python3 ble_set_secret.py 0e980548c8f91ec0              # random secret
  python3 ble_set_secret.py 0e980548c8f91ec0 076ff9...bc  # specific secret
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

UUID_ENCRYPTED = "6D2ADDA0-9AEA-11EA-BB37-0242AC130002"
UUID_ENCRYPTION_SETUP = "6D2ADFDA-9AEA-11EA-BB37-0242AC130002"
SALT_NEW = bytes.fromhex("bca9e39738e2611c25d243c985d3c592ccbee330e077b89d7978f5fc785cb5e8")
IV_SALT_NEW = bytes.fromhex("41e2e9eb5e5fa56e800e346d8c2b600742eb49839626faecdc37fb94a3a3c202")


class S:
    def __init__(self):
        self.pk = None; self.pub = None; self.ss = None; self.enc = None; self.dec = None
    def gen(self):
        self.pk = X25519PrivateKey.generate()
        self.pub = self.pk.public_key().public_bytes_raw()
        return self.pub
    def derive(self, peer):
        self.ss = self.pk.exchange(X25519PublicKey.from_public_bytes(peer))
        k = hashlib.sha1(SALT_NEW + self.ss).digest()[:16]
        iv = hashlib.sha1(IV_SALT_NEW + self.ss).digest()[:16]
        self.enc = Cipher(algorithms.AES(k), modes.CTR(iv)).encryptor()
        self.dec = Cipher(algorithms.AES(k), modes.CTR(iv)).decryptor()
    def encrypt(self, d):
        self.dec.update(d); return self.enc.update(d)
    def decrypt(self, d):
        self.enc.update(d); return self.dec.update(d)


class D(NSObject):
    def init(self):
        self = objc.super(D, self).init()
        self.rr = {}; self.re = {}; self.wr = {}; self.we = {}
        self.cp = 0; self.cd = asyncio.Event()
        return self
    def peripheral_didUpdateValueForCharacteristic_error_(self, p, c, e):
        u = str(c.UUID())
        self.rr[u] = (None if e else bytes(c.value() or b""), str(e) if e else None)
        if u in self.re: self.re[u].set()
    def peripheral_didWriteValueForCharacteristic_error_(self, p, c, e):
        u = str(c.UUID()); self.wr[u] = str(e) if e else "OK"
        if u in self.we: self.we[u].set()
    def peripheral_didUpdateNotificationStateForCharacteristic_error_(self, p, c, e): pass
    def peripheral_didDiscoverServices_(self, p, e):
        svcs = p.services() or []
        self.cp = len(svcs)
        if not svcs: self.cd.set()
        for s in svcs: p.discoverCharacteristics_forService_(None, s)
    def peripheral_didDiscoverCharacteristicsForService_error_(self, p, s, e):
        self.cp -= 1
        if self.cp <= 0: self.cd.set()


async def bw(d, p, c, data, t=8.0):
    u = str(c.UUID()); ev = asyncio.Event(); d.we[u] = ev
    p.writeValue_forCharacteristic_type_(CB.NSData.dataWithBytes_length_(data, len(data)), c, 0)
    try: await asyncio.wait_for(ev.wait(), timeout=t); return d.wr.get(u, "?")
    except asyncio.TimeoutError: return "timeout"

async def br(d, p, c, t=5.0):
    u = str(c.UUID()); ev = asyncio.Event(); d.re[u] = ev
    p.readValueForCharacteristic_(c)
    try: await asyncio.wait_for(ev.wait(), timeout=t); return d.rr.get(u, (None, "?"))
    except asyncio.TimeoutError: return None, "timeout"

def fc(svcs, uuid):
    t = uuid.upper()
    for svc in svcs:
        for ch in (svc.characteristics() or []):
            if str(ch.UUID()).upper() == t: return ch
    return None


async def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ble_set_secret.py <auth_token_hex> [secret_hex]")
        sys.exit(1)

    auth = bytes.fromhex(sys.argv[1])
    if len(sys.argv) >= 3:
        secret = bytes.fromhex(sys.argv[2])
    else:
        import os
        secret = os.urandom(54)
    print(f"Secret to write: {secret.hex()}")

    print("Scanning...")
    for a in range(3):
        devs = await BleakScanner.discover(timeout=5.0, return_adv=True)
        tgt = None
        for _, (dev, adv) in devs.items():
            if "Wireless SW" in (dev.name or adv.local_name or ""):
                print(f"Found: {dev.name}"); tgt = dev; break
        if tgt: break
        print("  retrying...")
    if not tgt: print("Not found"); return

    be = None
    for ca in range(3):
        try:
            if ca > 0:
                await asyncio.sleep(1)
                devs = await BleakScanner.discover(timeout=3.0, return_adv=True)
                for _, (dev, adv) in devs.items():
                    if "Wireless SW" in (dev.name or adv.local_name or ""): tgt = dev; break
            print(f"Connecting ({ca+1})...")
            be = BleakClientCoreBluetooth(tgt, timeout=10.0)
            async def noop(): pass
            be._get_services = noop
            await be.connect(False); break
        except Exception as e: print(f"  Failed: {e}"); be = None
    if not be or not be.is_connected: print("Could not connect"); return

    p = be._peripheral; d = D.alloc().init(); p.setDelegate_(d)
    p.discoverServices_(None)
    try: await asyncio.wait_for(d.cd.wait(), timeout=10.0)
    except: pass

    svcs = p.services() or []
    cs = fc(svcs, UUID_ENCRYPTION_SETUP); ce = fc(svcs, UUID_ENCRYPTED)
    if not cs or not ce: print("Chars not found"); return

    s = S(); pub = s.gen()
    r = await bw(d, p, cs, pub)
    if r != "OK": print(f"Kex failed: {r}"); return

    await asyncio.sleep(0.1)
    peer, err = await br(d, p, cs)
    if err or not peer or len(peer) != 32: print(f"Kex read failed"); return

    s.derive(peer)
    tlv = bytes([0x02, len(auth)]) + auth
    r = await bw(d, p, cs, s.encrypt(tlv))
    if r != "OK": print(f"Auth failed: {r}"); return
    await asyncio.sleep(0.1)
    resp, _ = await br(d, p, cs)
    if resp:
        s.decrypt(resp)  # must decrypt to keep cipher state in sync
        print(f"Auth OK")
    else: print("Auth failed"); return

    p.setNotifyValue_forCharacteristic_(True, ce)
    await asyncio.sleep(0.1)

    # Build POST sp/ss
    buf = bytearray()
    ep = b"sp/ss"
    buf.extend(struct.pack(">HH", 1, len(ep))); buf.extend(ep)
    buf.extend(struct.pack(">HH", 4, 1)); buf.append(1)  # POST
    buf.extend(struct.pack(">HH", 2, len(secret))); buf.extend(secret)

    enc_req = s.encrypt(bytes(buf))
    uu = str(ce.UUID()); d.re[uu] = asyncio.Event()
    r = await bw(d, p, ce, enc_req)
    if r != "OK": print(f"Write failed: {r}"); return
    await asyncio.sleep(0.1)
    resp, _ = await br(d, p, ce)
    if resp:
        dec = s.decrypt(resp)
        # Parse status
        off = 0
        while off + 4 <= len(dec):
            tag, ln = struct.unpack(">HH", dec[off:off+4]); off += 4
            val = dec[off:off+ln]; off += ln
            if tag == 3:
                st = val[0] if val else -1
                print(f"Write result: {'SUCCESS' if st == 0 else f'FAILED({st})'}")
                break

    # Verify
    buf2 = bytearray()
    buf2.extend(struct.pack(">HH", 1, len(ep))); buf2.extend(ep)
    buf2.extend(struct.pack(">HH", 4, 1)); buf2.append(0)  # GET
    enc_req2 = s.encrypt(bytes(buf2))
    d.re[uu] = asyncio.Event()
    r = await bw(d, p, ce, enc_req2)
    if r == "OK":
        await asyncio.sleep(0.1)
        resp, _ = await br(d, p, ce)
        if resp:
            dec = s.decrypt(resp)
            off = 0
            while off + 4 <= len(dec):
                tag, ln = struct.unpack(">HH", dec[off:off+4]); off += 4
                val = dec[off:off+ln]; off += ln
                if tag == 3 and len(val) > 1:
                    readback = val[1:]
                    if readback == secret:
                        print(f"Verified: secret restored successfully!")
                    else:
                        print(f"Mismatch: {readback.hex()[:40]}...")

    try: await be.disconnect()
    except: pass
    await asyncio.sleep(0.2)
    print("Done")


def run():
    loop = asyncio.new_event_loop()
    loop.set_exception_handler(lambda l, c: None)  # suppress bleak disconnect noise
    loop.run_until_complete(main())
    loop.close()

run()
