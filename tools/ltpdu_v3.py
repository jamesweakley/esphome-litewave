#!/usr/bin/env python3
"""
LTPDU v3 UDP client for Nanoleaf NL65 lights.

Implements the full protocol stack:
  - V3 binary framing (12-byte headers)
  - TLV2 auth encoding (1B tag, 2B BE length, value)
  - SRP-6a authentication (SHA-256, 2048-bit group)
  - CRC encrypted session (AES-128-CTR, dual cipher)
  - CCM encrypted session (AES-128-CCM, counter IV)
  - LTPDU command layer (GET/POST endpoints like sp/ss)

Protocol reverse-engineered from Nanoleaf APK (ltpdu_v3 package).
"""

import hashlib
import math
import os
import random
import socket
import struct
import sys
import time
from enum import IntEnum
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ──────────────────────────────────────────────────────────────────────────────
# Enums (from APK contract classes)
# ──────────────────────────────────────────────────────────────────────────────

class MessageType(IntEnum):
    Request = 1
    Response = 2
    Event = 3
    PublicMessage = 4
    Ack = 5

class UriType(IntEnum):
    Secure = 1
    LTPDU = 2
    Events = 3
    Identify = 4
    Info = 5

class MethodType(IntEnum):
    GET = 0
    POST = 1
    PUT = 2
    DELETE = 3

class ResponseCode(IntEnum):
    OK = 0
    NoContent = 1
    BadRequest = 2
    Unauthorized = 3
    PayloadTooLarge = 4
    InternalServerError = 5


class AuthErrorCode(IntEnum):
    ClientIdNotFound = 1
    VerificationFailed = 2
    MaxPairingsReached = 3
    PublicKeyNotSent = 4
    BadRequest = 5
    AuthTokenNotFound = 6


AUTH_ERROR_DESCRIPTIONS = {
    AuthErrorCode.ClientIdNotFound: "Client ID not found",
    AuthErrorCode.VerificationFailed: "Verification failed (invalid credentials)",
    AuthErrorCode.MaxPairingsReached: "Max pairings reached (all pairing slots full)",
    AuthErrorCode.PublicKeyNotSent: "Public key not sent",
    AuthErrorCode.BadRequest: "Bad request",
    AuthErrorCode.AuthTokenNotFound: "Auth Token Not Found on device — This token is no longer stored in the light's pairing slots (already cleared, evicted, or invalid).",
}


def describe_response_code(code: int, context: str = "", auth_err_code: Optional[int] = None) -> str:
    """Return human-readable explanation for LTPDU response / error codes."""
    descriptions = {
        0: "OK (Success)",
        1: "No Content",
        2: "Bad Request (malformed packet or parameters)",
        3: "Unauthorized (invalid pairing code or credentials)",
        4: "Payload Too Large",
        5: "Internal Error / Pairing Slots Full — The light has reached its maximum pairing slots (~4-5 clients). Perform a factory reset on the light (power cycle 5 times) to clear slots. You will have to rejoin any Matter fabrics again afterwards.",
        6: "Forbidden — Admin key required (POST 'sp/admin' first on fresh lights).",
    }
    desc = descriptions.get(code, f"Unknown error code {code}")
    if auth_err_code is not None:
        auth_desc = AUTH_ERROR_DESCRIPTIONS.get(auth_err_code, f"Auth error {auth_err_code}")
        desc = f"{desc} [{auth_desc}]"
    if context:
        return f"{context} failed: code {code} ({desc})"
    return f"Code {code}: {desc}"

class AuthTag(IntEnum):
    AuthenticationType = 0x01
    Salt = 0x02
    PublicKey = 0x03
    VerificationChallenge = 0x04
    AuthTokenRequest = 0x05
    AuthTokenResponse = 0x06
    SecureSessionType = 0x07
    Disconnect = 0x08
    Unpair = 0x09
    GetEventEncryptionData = 0x0A
    EventEncryptionKey = 0x0B
    EventEncryptionIV = 0x0C
    GenerateNewClientAuth = 0x0D
    ClientId = 0x0E
    SecureSessionVersion = 0x11
    Error = 0xF0


# ──────────────────────────────────────────────────────────────────────────────
# V3 Binary Framing
# ──────────────────────────────────────────────────────────────────────────────

def build_v3_request(message_id: int, client_id: int, uri_type: int,
                     method: int, data: bytes) -> bytes:
    """Build a v3 request packet: 12-byte header + data."""
    header = struct.pack("!BBHHBBI",
                         0x01,                # version
                         MessageType.Request,  # messageType
                         message_id & 0xFFFF,
                         client_id & 0xFFFF,
                         uri_type & 0xFF,
                         method & 0xFF,
                         len(data))
    return header + data


def parse_v3_response(raw: bytes) -> Tuple[int, int, int, int, int, bytes]:
    """Parse a v3 response: (version, msg_type, msg_id, client_id, resp_code, data)."""
    if len(raw) < 6:
        raise ValueError(f"Response too short: {len(raw)} bytes, hex: {raw.hex()}")

    version, msg_type = struct.unpack_from("!BB", raw, 0)

    if msg_type == MessageType.Ack:
        msg_id, client_id = struct.unpack_from("!HH", raw, 2)
        return version, msg_type, msg_id, client_id, 0, b""

    if len(raw) < 12:
        raise ValueError(f"Response too short for type {msg_type}: {len(raw)} bytes")

    msg_id, client_id, resp_code, data_len = struct.unpack_from("!HHHI", raw, 2)
    data = raw[12:12 + data_len]
    return version, msg_type, msg_id, client_id, resp_code, data


# ──────────────────────────────────────────────────────────────────────────────
# TLV2 Auth Format (1-byte tag + 2-byte BE length + value)
# ──────────────────────────────────────────────────────────────────────────────

def build_auth_tlv(tag: int, value: bytes) -> bytes:
    return struct.pack("!BH", tag & 0xFF, len(value)) + value


def build_auth_tlv_array(*tlvs: bytes) -> bytes:
    return b"".join(tlvs)


def parse_auth_tlvs(data: bytes) -> Dict[int, bytes]:
    result = {}
    offset = 0
    while offset < len(data):
        if offset + 3 > len(data):
            break
        tag = data[offset]
        length = struct.unpack_from("!H", data, offset + 1)[0]
        value = data[offset + 3:offset + 3 + length]
        result[tag] = value
        offset += 3 + length
    return result


# ──────────────────────────────────────────────────────────────────────────────
# LTPDU Command TLV (2-byte BE tag + 2-byte BE length + value) — same as v2
# ──────────────────────────────────────────────────────────────────────────────

def build_ltpdu_cmd(endpoint: str, value: bytes = None,
                    method: int = 0) -> bytes:
    """Build LTPDU v3 command TLV (2-byte BE tag + 2-byte BE length + value).

    Tags: ENDPOINT=1, PAYLOAD=2, RESPONSE=3, METHOD=4
    Methods: GET=0, POST=1, PUT=2, DELETE=3
    """
    ep = endpoint.encode("utf-8")
    tlv = struct.pack("!HH", 1, len(ep)) + ep  # ENDPOINT tag
    tlv += struct.pack("!HH", 2, len(value) if value else 0)  # PAYLOAD tag
    if value:
        tlv += value
    tlv += struct.pack("!HH", 4, 1) + bytes([method])  # METHOD tag
    return tlv


def parse_ltpdu_response(data: bytes) -> Tuple[str, int, bytes]:
    """Parse LTPDU v3 response TLV (2-byte BE tag + 2-byte BE length)."""
    offset = 0
    endpoint = ""
    status = -1
    value = b""
    while offset + 4 <= len(data):
        tag = struct.unpack_from("!H", data, offset)[0]
        length = struct.unpack_from("!H", data, offset + 2)[0]
        v = data[offset + 4:offset + 4 + length]
        if tag == 1:  # ENDPOINT
            endpoint = v.decode("utf-8", errors="replace")
        elif tag == 3:  # RESPONSE
            if len(v) >= 1:
                status = v[0]
                value = v[1:]
        elif tag == 2:  # PAYLOAD
            value = v
        offset += 4 + length
    return endpoint, status, value


# ──────────────────────────────────────────────────────────────────────────────
# SRP-6a Client (SHA-256, 2048-bit group)
# ──────────────────────────────────────────────────────────────────────────────

# SRP groups from APK BaseLTPDUv3Connection.java
SRP_NG_2048 = int(
    "21766174458617435773191008891802753781907668374255538511144643224689886235383"
    "84095721090901308605640157139971723580726658164960647214841029141336415219736"
    "44771808873956554837381150726774022351017625219015698207402931495296204193332"
    "66262073471054548368736039519702486226506248861060256971802984953561121442680"
    "15766800076142998822245709041387397397017192709399211475176516806361476111961"
    "54762334220964427831179712363716473338714143358957734746673089670508070055093"
    "20424799678417036867928316761272274230314067548291133582479583061439577559347"
    "101961771406173684378522703483495337037655006751328447510550299250924469288819"
)
SRP_NG_512 = int(
    "11229916235553671384460957561912561881437004243772597012148068303101566041140"
    "271835868089403470930092847368898606170616536123073256223246414212750058495475"
)
SRP_G = 2


def _int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes(math.ceil(n.bit_length() / 8), "big")


def _int_to_padded_bytes(n: int, length: int) -> bytes:
    b = _int_to_bytes(n)
    if len(b) < length:
        b = b"\x00" * (length - len(b)) + b
    return b


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _sha256_int(*parts: bytes) -> int:
    return int.from_bytes(_sha256(*parts), "big")


class SRP6aClient:
    """SRP-6a client matching APK SRP6aClient.java (SHA-256, g=2)."""

    def __init__(self, username: str, password: bytes, n: int = None):
        self.username = username
        self.password = password
        self.n = n if n is not None else SRP_NG_512
        self.g = SRP_G
        self.a = int.from_bytes(os.urandom(64), "big")  # 512-bit random
        self.A = pow(self.g, self.a, self.n)
        self.B: Optional[int] = None
        self.salt: Optional[int] = None
        self._session_key: Optional[bytes] = None
        self._M1: Optional[bytes] = None

    def get_public_key_bytes(self) -> bytes:
        return _int_to_bytes(self.A)

    def process_challenge(self, salt: bytes, B: bytes) -> bytes:
        """Process server's salt + public key, return client proof M1."""
        self.salt = int.from_bytes(salt, "big")
        self.B = int.from_bytes(B, "big")

        n_bytes = _int_to_bytes(self.n)
        g_bytes = _int_to_bytes(self.g)

        # k = H(N || g) — APK does NOT pad g (unlike RFC 5054)
        k = _sha256_int(n_bytes, g_bytes)

        # u = H(A || B)
        u = _sha256_int(_int_to_bytes(self.A), _int_to_bytes(self.B))

        # x = H(salt || H(username || ':' || password))
        inner = _sha256(self.username.encode("utf-8") + b":" + self.password)
        x = _sha256_int(_int_to_bytes(self.salt), inner)

        # S = (B - k * g^x)^(a + u*x) mod N
        S = pow(self.B - k * pow(self.g, x, self.n), self.a + u * x, self.n)

        # Session key K = H(S)
        self._session_key = _sha256(_int_to_bytes(S))

        # M1 = H( H(N) XOR H(g) || H(username) || salt || A || B || K )
        hN = bytearray(_sha256(n_bytes))
        hg = _sha256(g_bytes)  # APK uses unpadded g
        for i in range(len(hN)):
            hN[i] ^= hg[i]

        hu = _sha256(self.username.encode("utf-8"))

        self._M1 = _sha256(
            bytes(hN),
            hu,
            _int_to_bytes(self.salt),
            _int_to_bytes(self.A),
            _int_to_bytes(self.B),
            self._session_key,
        )
        return self._M1

    def verify_server_proof(self, M2: bytes) -> bool:
        """Verify server's proof M2 = H(A || M1 || K)."""
        expected = _sha256(
            _int_to_bytes(self.A),
            self._M1,
            self._session_key,
        )
        return M2 == expected

    def get_session_key(self) -> bytes:
        """Return 32-byte session key for encryption = H(H(S)) per APK getSessionKey()."""
        if self._session_key is None:
            raise RuntimeError("SRP not completed")
        return _sha256(self._session_key)


# ──────────────────────────────────────────────────────────────────────────────
# Encrypted Sessions
# ──────────────────────────────────────────────────────────────────────────────

class CrcEncryptedSession:
    """v3.0 AES-128-CTR dual-cipher session (from APK p236mg.a)."""

    def __init__(self, key: bytes, iv: bytes):
        cipher_enc = Cipher(algorithms.AES(key), modes.CTR(iv))
        cipher_dec = Cipher(algorithms.AES(key), modes.CTR(iv))
        self._enc = cipher_enc.encryptor()
        self._dec = cipher_dec.decryptor()

    def encrypt(self, data: bytes) -> bytes:
        self._dec.update(data)  # keep decrypt counter in sync
        return self._enc.update(data)

    def decrypt(self, data: bytes) -> bytes:
        self._enc.update(data)  # keep encrypt counter in sync
        return self._dec.update(data)


class CcmEncryptedSession:
    """v3.1/v3.2 AES-128-CCM session (from APK p236mg.b)."""

    def __init__(self, key: bytes, iv_base: bytes, iv_size: int,
                 initial_counter: int = 0):
        self._key = key
        self._iv_base = iv_base
        self._iv_size = iv_size
        self._counter = initial_counter

    def _build_iv(self) -> bytes:
        counter_bytes = struct.pack("!Q", self._counter)  # 8 bytes BE
        iv = bytearray(self._iv_size)
        if self._iv_size == 13:
            iv[0:5] = counter_bytes[3:8]
            iv[5:13] = self._iv_base[0:8]
        elif self._iv_size == 12:
            iv[0:4] = counter_bytes[4:8]
            iv[4:12] = self._iv_base[0:8]
        self._counter += 1
        return bytes(iv)

    def encrypt(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESCCM
        nonce = self._build_iv()
        cipher = AESCCM(self._key, tag_length=4)
        return cipher.encrypt(nonce, data, None)

    def decrypt(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESCCM
        nonce = self._build_iv()
        cipher = AESCCM(self._key, tag_length=4)
        return cipher.decrypt(nonce, data, None)


def create_session_from_srp(session_key: bytes, version_bytes: bytes):
    """Create the appropriate encrypted session from SRP session key + version."""
    aes_key = session_key[:16]

    if len(version_bytes) >= 2:
        major, minor = version_bytes[0], version_bytes[1]
    else:
        major, minor = 3, 0

    if major == 3 and minor == 0:
        # CRC session: iv = 8 zero bytes + sessionKey[16:24]
        iv = b"\x00" * 8 + session_key[16:24]
        print(f"  Session v3.0 (CRC/AES-CTR), key={aes_key.hex()}, iv={iv.hex()}")
        return CrcEncryptedSession(aes_key, iv)
    elif major == 3 and minor == 1:
        iv_base = session_key[16:24]
        print(f"  Session v3.1 (CCM-13), key={aes_key.hex()}, ivBase={iv_base.hex()}")
        return CcmEncryptedSession(aes_key, iv_base, iv_size=13)
    elif major == 3 and minor == 2:
        iv_base = session_key[16:24]
        print(f"  Session v3.2 (CCM-12), key={aes_key.hex()}, ivBase={iv_base.hex()}")
        return CcmEncryptedSession(aes_key, iv_base, iv_size=12)
    else:
        raise ValueError(f"Unknown session version {major}.{minor}")


# ──────────────────────────────────────────────────────────────────────────────
# V3 UDP Transport
# ──────────────────────────────────────────────────────────────────────────────

class UdpTransport:
    def __init__(self, host: str, port: int = 12566, timeout: float = 5.0):
        self.host = host.strip("[]")
        self.port = port
        self.timeout = timeout
        is_ipv6 = ":" in self.host
        family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        if is_ipv6:
            self._addr = (self.host, self.port, 0, 0)
        else:
            self._addr = (self.host, self.port)

    def send_recv(self, data: bytes, retries: int = 3) -> bytes:
        for attempt in range(retries):
            try:
                self.sock.sendto(data, self._addr)
                resp, _ = self.sock.recvfrom(4096)
                return resp
            except socket.timeout:
                if attempt < retries - 1:
                    print(f"  Timeout, retry {attempt + 2}/{retries}...")
                    continue
                raise

    def close(self):
        self.sock.close()


# ──────────────────────────────────────────────────────────────────────────────
# LTPDU V3 Session (ties everything together)
# ──────────────────────────────────────────────────────────────────────────────

class LtpduV3Session:
    def __init__(self, host: str, port: int = 12566):
        self.transport = UdpTransport(host, port)
        self.client_id = 0xFFFF
        self.msg_counter = random.randint(1, 0xFFFE)
        self.session = None  # encrypted session after auth

    def _next_msg_id(self) -> int:
        mid = self.msg_counter
        self.msg_counter = (self.msg_counter + 1) & 0xFFFF
        return mid

    def _send_secure(self, data: bytes) -> Tuple[int, bytes]:
        """Send a Secure request and return (response_code, response_data)."""
        pkt = build_v3_request(self._next_msg_id(), self.client_id,
                               UriType.Secure, MethodType.POST, data)
        raw = self.transport.send_recv(pkt)
        ver, mtype, mid, cid, rcode, rdata = parse_v3_response(raw)
        if cid != 0xFFFF:
            self.client_id = cid
        return rcode, rdata

    def authenticate(self, service_name: str, auth_token: bytes):
        """Run SRP-6a AuthToken authentication and establish encrypted session."""
        self._srp_auth(service_name, auth_token, pairing_code=False)

    def pair(self, service_name: str, pairing_code: str) -> bytes:
        """Run SRP-6a PairingCode authentication, get auth token, establish session.

        service_name: mDNS service name (e.g. 'Nanoleaf DL 789-6958')
        pairing_code: 11-digit Matter setup code, hyphens optional (e.g. '1640-700-5590')
        """
        code = pairing_code.replace("-", "")
        password = bytes(int(c) for c in code)  # digit VALUES, not ASCII
        return self._srp_auth(service_name, password, pairing_code=True)

    def _srp_auth(self, service_name: str, password: bytes,
                  pairing_code: bool = False) -> Optional[bytes]:
        """Run SRP-6a authentication. Returns auth_token if PairingCode flow."""
        auth_type = 1 if pairing_code else 2  # PairingCode=1, AuthToken=2
        label = "pairing code" if pairing_code else f"token {password.hex()}"
        print(f"Authenticating as '{service_name}' with {label}...")

        # Username = service name truncated at first hyphen
        username = service_name.split("-")[0].rstrip()
        srp = SRP6aClient(username, password)

        # Step 1: send client public key + auth type
        A_bytes = srp.get_public_key_bytes()
        step1_tlv = build_auth_tlv_array(
            build_auth_tlv(AuthTag.PublicKey, A_bytes),
            build_auth_tlv(AuthTag.AuthenticationType, bytes([auth_type])),
            build_auth_tlv(AuthTag.SecureSessionType, bytes([2])),
        )
        print(f"  Step 1: sending A ({len(A_bytes)} bytes)...")
        rcode, rdata = self._send_secure(step1_tlv)
        tlvs = parse_auth_tlvs(rdata) if rdata else {}
        auth_err = tlvs[AuthTag.Error][0] if AuthTag.Error in tlvs and tlvs[AuthTag.Error] else None

        if rcode != ResponseCode.OK:
            raise Exception(describe_response_code(rcode, "Step 1 (Public Key Exchange)", auth_err))

        if auth_err is not None:
            raise Exception(f"Step 1 error: {describe_response_code(rcode, auth_err_code=auth_err)}")

        salt = tlvs.get(AuthTag.Salt)
        B = tlvs.get(AuthTag.PublicKey)
        version = tlvs.get(AuthTag.SecureSessionVersion, bytes([3, 0]))

        if salt is None or B is None:
            raise Exception(f"Step 1: missing salt or B. Got tags: {list(tlvs.keys())}")

        print(f"  Step 1 OK: salt={len(salt)}B, B={len(B)}B, version={list(version)}")

        # Step 2: compute M1 and send
        M1 = srp.process_challenge(salt, B)
        step2_tlv = build_auth_tlv(AuthTag.VerificationChallenge, M1)
        print(f"  Step 2: sending M1 ({len(M1)} bytes)...")
        rcode, rdata = self._send_secure(step2_tlv)
        tlvs = parse_auth_tlvs(rdata) if rdata else {}
        auth_err = tlvs[AuthTag.Error][0] if AuthTag.Error in tlvs and tlvs[AuthTag.Error] else None

        if rcode != ResponseCode.OK:
            raise Exception(describe_response_code(rcode, "Step 2 (Challenge Verification)", auth_err))

        if auth_err is not None:
            raise Exception(f"Step 2 error: {describe_response_code(rcode, auth_err_code=auth_err)}")

        M2 = tlvs.get(AuthTag.VerificationChallenge)
        if M2 is None:
            raise Exception(f"Step 2: missing M2. Got tags: {list(tlvs.keys())}")

        if not srp.verify_server_proof(M2):
            raise Exception("Step 2: server proof verification failed (pairing code incorrect?)")

        print("  Step 2 OK: server proof verified")

        # Derive session encryption
        session_key = srp.get_session_key()
        self.session = create_session_from_srp(session_key, version)

        # Step 3: get auth token (PairingCode flow only)
        auth_token_result = None
        if pairing_code:
            step3_tlv = build_auth_tlv(AuthTag.AuthTokenRequest, b"")
            encrypted = self.session.encrypt(step3_tlv)
            print(f"  Step 3: requesting auth token...")
            rcode, rdata = self._send_secure(encrypted)
            if rcode != ResponseCode.OK:
                raise Exception(describe_response_code(rcode, "Step 3 (Auth Token Request)"))
            decrypted = self.session.decrypt(rdata)
            tlvs = parse_auth_tlvs(decrypted)
            auth_token_result = tlvs.get(AuthTag.AuthTokenResponse)
            if auth_token_result:
                print(f"  Step 3 OK: auth token = {auth_token_result.hex()}")
            else:
                print(f"  Step 3: no auth token in response. Tags: {list(tlvs.keys())}")

        print("  Authentication complete!")
        return auth_token_result

    def _send_ltpdu(self, endpoint: str, value: bytes = None,
                    method: int = 0) -> Tuple[str, int, bytes]:
        """Send an encrypted LTPDU command and return (endpoint, status, value).
        method: 0=GET, 1=POST, 2=PUT, 3=DELETE
        """
        if self.session is None:
            raise RuntimeError("Not authenticated")

        payload = build_ltpdu_cmd(endpoint, value, method=method)
        encrypted = self.session.encrypt(payload)

        # LTPDU commands always use POST in the v3 frame header
        pkt = build_v3_request(self._next_msg_id(), self.client_id,
                               UriType.LTPDU, MethodType.POST, encrypted)
        raw = self.transport.send_recv(pkt)
        ver, mtype, mid, cid, rcode, rdata = parse_v3_response(raw)

        if rcode != ResponseCode.OK:
            raise Exception(describe_response_code(rcode, f"LTPDU '{endpoint}'"))

        decrypted = self.session.decrypt(rdata)
        return parse_ltpdu_response(decrypted)

    def get(self, endpoint: str) -> Tuple[int, bytes]:
        """GET an endpoint, return (status, value)."""
        ep, status, value = self._send_ltpdu(endpoint, method=0)
        return status, value

    def post(self, endpoint: str, value: bytes) -> Tuple[int, bytes]:
        """POST to an endpoint, return (status, response_value)."""
        ep, status, rval = self._send_ltpdu(endpoint, value, method=1)
        return status, rval

    def put(self, endpoint: str, value: bytes) -> Tuple[int, bytes]:
        """PUT to an endpoint, return (status, response_value)."""
        ep, status, rval = self._send_ltpdu(endpoint, value, method=2)
        return status, rval

    def delete(self, endpoint: str) -> Tuple[int, bytes]:
        """DELETE an endpoint, return (status, response_value)."""
        ep, status, rval = self._send_ltpdu(endpoint, method=3)
        return status, rval

    def unpair(self):
        """Send Unpair command to free this client pairing slot on the light, then close."""
        if self.session is not None:
            try:
                unpair_tlv = build_auth_tlv(AuthTag.Unpair, b"")
                encrypted = self.session.encrypt(unpair_tlv)
                pkt = build_v3_request(self._next_msg_id(), self.client_id,
                                       UriType.Secure, MethodType.POST, encrypted)
                self.transport.send_recv(pkt)
            except Exception:
                pass
            self.session = None
        self.transport.close()

    def disconnect(self):
        """Send disconnect and close (retains pairing slot on light)."""
        if self.session is not None:
            try:
                disc_tlv = build_auth_tlv(AuthTag.Disconnect, b"")
                encrypted = self.session.encrypt(disc_tlv)
                pkt = build_v3_request(self._next_msg_id(), self.client_id,
                                       UriType.Secure, MethodType.POST, encrypted)
                self.transport.send_recv(pkt)
            except Exception:
                pass
            self.session = None
        self.transport.close()

    def close(self):
        self.transport.close()


# ──────────────────────────────────────────────────────────────────────────────
# CLI: quick test against a light
# ──────────────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="LTPDU v3 client")
    parser.add_argument("host", help="Light IPv6 address (with or without brackets)")
    parser.add_argument("service_name", help="mDNS service name (SRP username)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--token", help="Auth token hex (for AuthToken auth)")
    group.add_argument("--pair", help="Matter pairing code (for PairingCode auth)")
    parser.add_argument("--port", type=int, default=12566)
    parser.add_argument("--cmd", default="info",
                        choices=["info", "on", "off", "read-ss", "write-ss", "unpair"],
                        help="Command to run after auth")
    parser.add_argument("--secret", help="New shared secret hex (for write-ss)")
    args = parser.parse_args()

    session = LtpduV3Session(args.host, args.port)

    try:
        if args.pair:
            new_token = session.pair(args.service_name, args.pair)
            if new_token:
                print(f"\n  >>> New auth token: {new_token.hex()} <<<")
                print(f"  Use --token {new_token.hex()} for future connections\n")
        else:
            session.authenticate(args.service_name, bytes.fromhex(args.token))

        if args.cmd == "unpair":
            print("\n--- Unpairing Client Slot ---")
            session.unpair()
            print("  ✓ Unpair command sent. Client slot released on device.")
            return

        elif args.cmd == "info":
            print("\n--- Device Info ---")
            status, value = session.get("di")
            print(f"  Status: {status}, Data ({len(value)} bytes): {value.hex()}")

        elif args.cmd == "on":
            print("\n--- Light ON ---")
            status, _ = session.post("lb/0/oo", b"\x01")
            print(f"  Status: {status}")

        elif args.cmd == "off":
            print("\n--- Light OFF ---")
            status, _ = session.post("lb/0/oo", b"\x00")
            print(f"  Status: {status}")

        elif args.cmd == "read-ss":
            print("\n--- Read Shared Secret ---")
            status, value = session.get("sp/ss")
            print(f"  Status: {status}")
            if status == 0:
                print(f"  Secret ({len(value)} bytes): {value.hex()}")
            else:
                print(f"  Error: {value.hex()}")

        elif args.cmd == "write-ss":
            if not args.secret:
                print("Error: --secret required for write-ss")
                sys.exit(1)
            s = args.secret.strip().replace(" ", "").replace(":", "")
            if s.lower().startswith("0x"):
                s = s[2:]
            if len(s) > 108:
                print(f"Error: shared secret too long ({len(s)} hex chars, max 108)")
                sys.exit(1)
            s = s.rjust(108, "0")
            try:
                new_secret = bytes.fromhex(s)
            except ValueError as e:
                print(f"Error: invalid hexadecimal in shared secret: {e}")
                sys.exit(1)
            print(f"\n--- Write Shared Secret ({len(new_secret)} bytes) ---")
            status, _ = session.post("sp/ss", new_secret)
            print(f"  Write status: {status}")
            if status == 0:
                status2, readback = session.get("sp/ss")
                if readback == new_secret:
                    print("  Verified: readback matches!")
                else:
                    print(f"  WARNING: readback differs: {readback.hex()}")

        session.disconnect()

    except Exception as e:
        print(f"\nError: {e}")
        session.close()
        sys.exit(1)


if __name__ == "__main__":
    main()
