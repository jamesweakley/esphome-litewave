# Nanoleaf LTPDU v3 Protocol & Litewave Provisioning Reference

Reverse-engineered protocol documentation for Nanoleaf devices running firmware 5.x (LTPDU v3). Covers authentication, encrypted sessions, and Litewave control group registration. Verified against NL65 downlights with firmware 5.1.45.

## Transport

| Protocol | Port | Discovery | Firmware |
|----------|------|-----------|----------|
| LTPDU v3 (UDP) | 12566 | mDNS `_ltpdu._udp.local.` | >= 5.0.0 |
| LTPDU v2 (CoAP) | 5653 | mDNS `_ltpdu._udp.local.` | < 5.0.0 |

All communication uses IPv6 (Thread mesh-local addresses). The mDNS TXT record contains `srcvers` (firmware version), `md` (model, e.g. `NL65`), `eui64`, and `id` (pairing ID).

## V3 Binary Frame Format

All frames use a 12-byte big-endian header followed by a variable-length payload.

### Request Frame

```
Offset  Size  Field
0       1B    Version (0x03 over UDP, 0x01 over BLE)
1       1B    MessageType (1=Request)
2       2B    MessageID (uint16, random)
4       2B    ClientID (uint16, 0xFFFF for initial, server assigns)
6       1B    UriType
7       1B    Method
8       4B    DataLength (uint32, payload size)
12+     var   Payload (TLV-encoded)
```

### Response Frame

```
Offset  Size  Field
0       1B    Version
1       1B    MessageType (2=Response)
2       2B    MessageID (echoes request)
4       2B    ClientID
6       2B    ResponseCode (uint16)
8       4B    DataLength
12+     var   Payload
```

### URI Types

| Value | Name | Purpose |
|-------|------|---------|
| 1 | Secure | SRP authentication and session management |
| 2 | LTPDU | Authenticated device commands (light control, provisioning) |
| 3 | Events | Event subscription |
| 4 | Identify | Flash the light (no auth required) |
| 5 | Info | Device information (no auth required) |

### Methods

| Value | Name |
|-------|------|
| 0 | GET |
| 1 | POST |
| 2 | PUT |
| 3 | DELETE |

### Response Codes

| Value | Name |
|-------|------|
| 0 | OK |
| 1 | NoContent |
| 2 | BadRequest |
| 3 | Unauthorized |
| 4 | PayloadTooLarge |
| 5 | InternalServerError |

## TLV Encoding

### Auth TLVs (Secure URI)

Used for SRP authentication messages. Format: `1-byte tag + 2-byte BE length + value`.

| Tag | Name | Description |
|-----|------|-------------|
| 0x01 | AuthenticationType | `0x01`=PairingCode, `0x02`=AuthToken |
| 0x02 | Salt | 32-byte SRP salt (Step 1 response) |
| 0x03 | PublicKey | Client A or server B (Step 1) |
| 0x04 | VerificationChallenge | Client M1 / server M2 (Step 2) |
| 0x05 | AuthTokenRequest | Empty, sent in Step 3 |
| 0x06 | AuthTokenResponse | Auth token bytes (Step 3 response) |
| 0x07 | SecureSessionType | `0x01`=ConnectionDependent, `0x02`=ConnectionIndependent |
| 0x08 | Disconnect | Signal session end |
| 0x09 | Unpair | Remove stored credentials |
| 0x11 | SecureSessionVersion | 2 bytes: [major, minor] e.g. [3, 2] |
| 0xF0 | Error | Error code byte |

### Error Codes (tag 0xF0)

| Value | Name |
|-------|------|
| 1 | ClientIdNotFound |
| 2 | VerificationFailed |
| 3 | MaxPairingsReached |
| 4 | PublicKeyNotSent |
| 5 | BadRequest |
| 6 | AuthTokenNotFound |

### Command TLVs (LTPDU URI)

Used for device commands inside an authenticated session. Format: `2-byte BE tag + 2-byte BE length + value` (same format as V2 LTPDU commands).

| Tag | Direction | Purpose |
|-----|-----------|---------|
| 0x0001 | Request/Response | Endpoint path (UTF-8, e.g. `"di"`, `"lb/0/oo"`, `"sp/ss"`) |
| 0x0002 | Request | Payload value (zero-length for GET) |
| 0x0003 | Response | Status byte (0=OK) + response value |
| 0x0004 | Request | Method byte (0=GET, 1=POST, 2=PUT, 3=DELETE) |

Note: Command TLVs use 2-byte tags while Auth TLVs (Secure URI) use 1-byte tags. Both use 2-byte BE lengths.
| 0x0003 | Response | Status byte + response value |
| 0x0004 | Request | Explicit method ID (optional) |

## SRP-6a Authentication

### Parameters

| Parameter | Value |
|-----------|-------|
| Hash | SHA-256 |
| Generator (g) | 2 |
| Group (N) | Custom 512-bit value (see below) — used for Matter Essentials models (NL65, NL55v2, etc.) |
| k computation | `k = H(N_bytes \|\| g_bytes)` — g is NOT padded (differs from RFC 5054) |
| u computation | `u = H(A_bytes \|\| B_bytes)` — neither value padded |

**N (NG_512, 512 bits):**
```
d66aafe8e245f9ac245a199f62ce61ab8fa90a4d80c71cd2
adfd0b9da163b29f2a34afbdb3b1b5d0102559ce63d8b6e8
6b0aa59c14e79d4aa62d1748e4249df3
```

Note: this N is composite (divisible by 5). This is intentional — both the app and device firmware use this exact value. Verified in the macOS `libLtpduv3ClientManager.dylib` at symbol `NL::NLSRP::ng512`.

### Username Derivation

The SRP username is the mDNS service name **truncated at the first hyphen**:

```
serviceName.split("-")[0]
```

Examples:
- Service name `"Nanoleaf DL 789-6958"` → username `"Nanoleaf DL 789"`
- Service name `"Nanoleaf Lightstrip ffff"` → username `"Nanoleaf Lightstrip ffff"` (no hyphen)

Source: Nanoleaf Desktop app JavaScript function `cTe(name) { return name.split("-")[0] ?? "" }`.

### Password Encoding

For **PairingCode** authentication (type 1), the password is the 11-digit Matter setup code with each character converted to its numeric digit value:

```
"16407005590" → bytes [0x01, 0x06, 0x04, 0x00, 0x07, 0x00, 0x00, 0x05, 0x05, 0x09, 0x00]
```

This is NOT ASCII encoding. Each character `c` becomes `Number(c)` (JavaScript) or `digitToInt(c)` (Kotlin), producing a byte with value 0-9.

The pairing code is the 11-digit Matter manual pairing code printed on the device, with hyphens stripped. For QR code scans, the app decodes the Matter payload and reconstructs the 11-digit code.

For **AuthToken** authentication (type 2), the password is the raw auth token bytes obtained from Step 3 of a previous PairingCode session.

### SRP Computation

```
x     = H(salt_bytes || H(username_utf8 + ":" + password_bytes))
v     = g^x mod N
k     = H(N_bytes || g_bytes)
u     = H(A_bytes || B_bytes)
S     = (B - k*v)^(a + u*x) mod N
K     = H(S)                          -- session key used in M1/M2
M1    = H(XOR(H(N), H(g)) || H(username) || salt || A || B || K)
M2    = H(A || M1 || K)
```

The device sends B **unreduced** (B = k*v + g^b without mod N), resulting in 96-byte B values for NG_512. All byte conversions use unsigned big-endian with no leading zeros (equivalent to Java's `BigInteger.toByteArray()` with sign byte stripped).

The encryption key returned by `getSessionKey()` is `H(K) = H(H(S))` — a double SHA-256 hash. M1/M2 use the single-hash `K = H(S)`.

### Three-Step Authentication Flow

**Step 1** — Client → Server (Secure POST):
```
TLV(0x01=AuthType, [1 or 2])
TLV(0x03=PublicKey, A_bytes)        # 64 bytes for NG_512
TLV(0x07=SessionType, [2])          # ConnectionIndependent
```

Server → Client:
```
TLV(0x02=Salt, salt_bytes)          # 32 bytes
TLV(0x03=PublicKey, B_bytes)        # 96 bytes (unreduced)
TLV(0x11=Version, [major, minor])   # e.g. [3, 2]
```

**Step 2** — Client → Server (Secure POST):
```
TLV(0x04=Challenge, M1)             # 32 bytes
```

Server → Client:
```
TLV(0x04=Challenge, M2)             # 32 bytes
```

**Step 3** (PairingCode flow only) — encrypted from here on:

Client → Server:
```
TLV(0x05=AuthTokenRequest, b"")
```

Server → Client:
```
TLV(0x06=AuthTokenResponse, token)  # 8 bytes
```

Save the auth token for future AuthToken (type 2) sessions.

## Encrypted Session

After SRP Step 2, subsequent Secure requests/responses are encrypted. The encryption mode depends on the `SecureSessionVersion` returned in Step 1.

### Key Derivation

```
session_key = H(H(S))               # 32 bytes (double SHA-256)
aes_key     = session_key[0:16]      # first 16 bytes
iv_base     = session_key[16:24]     # next 8 bytes
```

### Version 3.2 — AES-128-CCM (current NL65 firmware)

- **Mode**: AES-128-CCM with 12-byte nonce and 4-byte authentication tag
- **Nonce**: `counter[4:8] || iv_base[0:8]` (4 bytes counter + 8 bytes base = 12 bytes)
- **Counter**: starts at 0, increments for each encrypt or decrypt operation
- **Tag**: 4 bytes, appended to ciphertext

### Version 3.1 — AES-128-CCM (13-byte nonce)

Same as 3.2 but with 13-byte nonce: `counter[3:8] || iv_base[0:8]`.

### Version 3.0 — AES-128-CTR (legacy)

- **Mode**: AES-128-CTR with dual synchronized ciphers
- **IV**: `0x0000000000000000 || iv_base[0:8]` (16 bytes)

## LTPDU Endpoints

All accessed via LTPDU POST/GET within an authenticated session.

| Endpoint | R/W | Description |
|----------|-----|-------------|
| `di` | R | Device info: hwver + fwver + serial + eui64 |
| `lb/0/oo` | R/W | Light on/off: `0x01` on, `0x00` off |
| `lb/0/pb` | R/W | Brightness (uint16 BE, 0-65535) |
| `lb/0/hu` | R/W | Hue (uint16 BE) |
| `lb/0/sa` | R/W | Saturation (uint16 BE) |
| `lb/0/ct` | R/W | Color temperature (uint16 BE, mireds) |
| `lb/0/cm` | R | Color mode |
| `lb/0/id` | W | Identify (flash light) |
| `sp/ss` | R/W | Shared secret (54 bytes, Litewave control group) |
| `sp/0/ss` | R/W | Shared secret (alternate path) |
| `sp/0/pi` | R/W | PAN ID (Litewave 802.15.4 channel) |
| `ci` | W | Command interface (scenes, JSON commands) |

## Litewave Control Group Registration

Litewave is Nanoleaf's proprietary protocol for low-latency light control over IEEE 802.15.4 radio (Thread). A Sense+ switch broadcasts commands on the Litewave PAN, and all lights with the matching shared secret respond.

### Shared Secret (sp/ss)

The shared secret is a **54-byte** value that determines which control group a light belongs to. All lights in the same group share the same secret. Writing a new secret to a light adds it to that group.

### Provisioning Flow

1. **Discover** lights via mDNS (`_ltpdu._udp.local.`, port 12566)
2. **Authenticate** via SRP-6a (PairingCode for new devices, AuthToken for known devices)
3. **Read** current secret: `GET sp/ss` → 54 bytes (or empty if unprovisioned)
4. **Write** new secret: `POST sp/ss` with 54-byte value
5. **Verify**: `GET sp/ss` and confirm readback matches

### JSON Provisioning (via `ci` endpoint)

Alternative method using the command interface:

```json
{
  "spParams": {
    "nlPropParams": {
      "ss": "<54-byte-hex-string>",
      "pi": 15217,
      "acl": ""
    }
  }
}
```

Where `pi` is the PAN ID as a decimal integer (e.g. `0x3B71` = `15217`).

## Rate Limiting

The device stops responding to Secure POST after approximately 2-3 failed SRP Step 2 attempts. A power cycle resets the rate limiter. Info GET and Identify POST are not affected.

## V2 Legacy Protocol (Firmware < 5.0.0)

Older firmware uses CoAP over UDP port 5653 with X25519 key exchange instead of SRP. The auth flow is simpler: ECDH key exchange → AES-128-CTR encrypted channel → send pairing code or auth token in-band.

Key derivation uses SHA-1:
```
key = SHA1("AES-NL-OPENAPI-KEY" + ecdh_shared)[:16]
iv  = SHA1("AES-NL-OPENAPI-IV"  + ecdh_shared)[:16]
```

Firmware >= 5.0.0 on NL65 models replaces these labels with 32-byte hex constants (see `ha-nanoleaf-ltpdu` integration for values). The V2 protocol is completely dead on firmware 5.1.45 NL65 devices — ports 5653 and 5683 do not respond.
