# Nanoleaf Litewave Protocol - Validated Findings

## Overview

This project reverse-engineers the Nanoleaf Litewave protocol used by Sense+ switches (NL44) to control NL65 Essentials Downlights. The goal is per-room control from a wall-mounted ESP32-C6, working instantly after power cycle without WiFi or Thread dependency.

## Protocol Summary

Litewave is a simple fire-and-forget broadcast protocol over IEEE 802.15.4 (not Thread):

| Parameter | Value |
|-----------|-------|
| Radio | IEEE 802.15.4 |
| Channel | 26 (0x1A) |
| PAN ID | 0x3411 |
| Destination | 0xFFF0 (multicast) |
| FCF | 0x1801 (data frame, no security, no source address) |
| Frame version | 1 |

### Frame Structure

```
802.15.4 MAC header:
  FCF (2 bytes, LE)  = 0x1801
  DSN (1 byte)       = sequence number (changes per button press, used by ESPHome)
  Dst PAN (2 bytes)  = 0x3411
  Dst Addr (2 bytes) = 0xFFF0

Payload (18 bytes):
  [0]     TTL / retry counter (starts at 0x09, counts down per retransmit)
  [1]     Command type (0x00 for ON/OFF)
  [2-15]  14-byte token (changes per button press, derived from shared secret)
  [16]    Trailer byte (0xA6 for multicast)
  [17]    Copy of TTL
```

### Key Properties

- **Tokens are rolling but replayable**: Each button press generates a different 14-byte token, but old tokens replay indefinitely — no replay window or counter check.
- **DSN (sequence number) matters**: Lights reject frames if the DSN doesn't match a previously seen value. Captured DSN must be used in replay.
- **Destination 0xFFF0 is the only accepted address**: Unicast to EUI-64, short addresses, or other multicast addresses does not work.
- **Token derivation uses the shared secret**: Changing `sp/ss` on the switch breaks its ability to control lights, confirming the 54-byte shared secret is an input to token generation. The exact derivation algorithm is in the Sense+ firmware (EFR32 SoC), not in the APK.
- **No MAC-layer security**: The FCF security bit is 0. There is no aux security header, no frame counter. The 14-byte token is pure application-layer authentication — all crypto is Nanoleaf's custom firmware code, not standard 802.15.4 security.

## Token Structure (Detailed Analysis)

From a 229-token wraparound analysis capturing 5 repeat pairs at the same DSN values:

```
Bytes 0-1:         PRF(key, DSN) — 16 deterministic bits, identical across ALL switches in a home
Byte 2 bits 7-3:   PRF(key, DSN) — 5 more deterministic bits (identical in same-DSN repeat pairs)
Byte 2 bits 2-0:   3-bit embedded nonce (changes per press; XOR=0x07 between same-DSN repeats)
Bytes 3-13:        11 bytes — MAC/ciphertext dependent on (key, DSN, nonce, switch_pairing_id)
```

Total = 21 deterministic bits + 3-bit embedded nonce + 88-bit per-press output = 14 bytes

Key observations:
- Bytes 0-1 are home-wide (same for all switches sharing the same SS)
- Bytes 3-13 vary per-switch (different pairing_ids produce different output)
- The 3-bit nonce provides 8 possible token variants per DSN, all valid
- Old tokens replay indefinitely — there is no replay window or counter check
- XOR between tokens from the original SS and an all-zeros SS at the same DSN is NOT constant, confirming AES-based derivation (not XOR/HMAC)

### Token Derivation — What's Known

The token derivation algorithm remains unknown. Exhaustive testing covered:
- 88+ key derivations from the 54-byte shared secret
- AES-ECB, AES-CTR, AES-CBC, AES-CMAC, AES-CCM (with various MIC lengths)
- HMAC-SHA256, HMAC-SHA1, BLAKE2s, ChaCha20
- All standard 802.15.4 nonce constructions
- DSN-only nonces (correct, since no frame counter exists)
- 680+ AES-CCM combinations with different key/nonce/AAD formulations

The key derivation likely follows the LTPDU pattern: `SHA1(LABEL + shared_secret)[:16]` — but the label string is embedded in the encrypted EFR32 firmware and cannot be extracted.

## Control Group Save — What the App Writes

Captured via smali-patched APK on 2026-10-13. When the Nanoleaf app saves a control group, it writes these values to each device over LTPDUv3:

| Order | Endpoint | Value | Notes |
|-------|----------|-------|-------|
| 1 | `sp/ss` | 54 random bytes | Identical for all devices in the home |
| 2 | `sp/pi` | 2 bytes (PAN ID) | e.g. `3b71` |
| 3 | `sp/mc` | integer (channel) | e.g. 26 |
| 4 | `sp/admin` | 2 bytes (admin key) | Random, non-zero, per-home |
| 5 | `sp/llc/acl` | TLV (ACL) | Lights only — authorized switch pairing_ids |
| 6 | motion_timeout | integer | e.g. 1200 seconds |
| 7 | fade_out | integer | e.g. 180 seconds |

The **only security-relevant data** is the 54-byte shared secret. There is no additional key material, no derived key, no IV, no nonce seed sent during provisioning. The firmware derives everything for token generation from those 54 bytes alone.

## SensePlus Configuration (Cloud Data)

Retrieved from Nanoleaf cloud sync and confirmed readable/writable via BLE to the Sense+ switch:

| Endpoint | Cloud Key | Example Value | Description |
|----------|-----------|---------------|-------------|
| `sp/ss` | `sharedSecret` | 54 random bytes | Litewave token derivation key |
| `sp/pi` | `panID` | `3b71` | 802.15.4 PAN ID |
| `sp/admin` | `adminKey` | `e676` | Admin key |
| `sp/mc` | `preferredChannel` | `1a` (26) | Radio channel |

## Per-Room Control System — PROVEN WORKING

### The Problem

All lights provisioned by the same Sense+ switch respond to that switch's tokens, regardless of which "control group" the app assigns them to. The `controlGroupId` only affects app-level UI, not the Litewave protocol.

### The Solution

Each light stores its own copy of the shared secret (`sp/ss`). If different lights have different secrets, they respond to different tokens — **cryptographic isolation without needing to understand the token algorithm**.

You only need **one physical Sense+ switch** to set up any number of rooms. The switch is temporarily programmed with each room's secret to generate that room's tokens, then the ESP32 replays them independently.

### Complete Per-Room Setup Workflow

```
For each room:
  1. Generate a unique 54-byte shared secret: os.urandom(54)
  2. Write the secret to the switch via BLE:
       python3 ble_write_ss.py "Nanoleaf Wireless SW 1D9" "0242-362-0007"
  3. Write the same secret to the room's lights via LTPDU/UDP:
       python3 provision_v3.py --host <light_ipv6> --name <light_name> --code <pairing_code> --secret <hex>
  4. Flash ESP32-C6 with sniffer firmware
  5. Capture ON/OFF tokens:
       python3 capture_tokens.py --group-name <room_name>
  6. Flash ESP32-C6 with transmitter firmware to verify:
       python3 lw_replay.py on <seq> <token>
       python3 lw_replay.py off <seq> <token>
  7. Repeat from step 1 for the next room (reuse the same physical switch)

Once all rooms are captured, configure ESPHome with per-room token sets.
The ESP32 replays the correct tokens per room — each room is cryptographically isolated.
```

### Three-Way Isolation Proof

Tested on 2026-10-13 with two groups:

| Test | Expected | Result |
|------|----------|--------|
| Group A token → light with home SS | Toggle | **Confirmed** |
| Group A token → light with group B SS | No effect | **Confirmed** |
| Group B token → light with group B SS | Toggle | **Confirmed** |
| Group B token → light with home SS | No effect | **Confirmed** |
| Restore home SS → switch toggles again | Toggle | **Confirmed** |

Matter/HomeKit control is **completely unaffected** by `sp/ss` changes — Litewave is an independent protocol layer.

### Validated Steps

| Step | Method | Status |
|------|--------|--------|
| Write `sp/ss` to switch | BLE legacy protocol (`ble_write_ss.py`) | **Confirmed working** |
| Read `sp/ss`, `sp/pi`, `sp/admin`, `sp/mc` from switch | BLE legacy protocol | **Confirmed working** |
| Write `sp/ss` to individual lights | LTPDU v3 over UDP (`provision_v3.py`) | **Confirmed working** |
| Changing `sp/ss` isolates groups | Physical test (three-way proof) | **Confirmed** |
| Token capture | ESP32-C6 sniffer + `capture_tokens.py` | **Confirmed working** |
| Token replay | ESP32-C6 transmitter + `lw_replay.py` | **Confirmed working** |
| Cross-group replay rejection | ESP32 replay across groups | **Confirmed** |
| SS write takes effect immediately | No device reboot needed | **Confirmed** |

### What Does NOT Work

- **App-mediated group isolation**: The Nanoleaf app syncs the shared secret from cloud to all lights, overwriting per-light secrets even when lights are powered off (syncs on next power-on). You must avoid saving control groups in the app after provisioning.
- **Per-light Litewave addressing**: Only destination 0xFFF0 is accepted. No unicast.
- **EUI-64 addressing in Litewave**: FCF 0x011C with extended addressing is ignored by lights.
- **Provisioning via LTPDU v2**: The `sp/*` endpoints return 0x04 (not found) on port 5653.
- **Auto-incrementing sequence numbers**: Lights reject frames with unexpected DSN values.

### Gotchas and Pitfalls

- **Light pairing slots**: Each `session.pair()` call on a light consumes a slot (max ~4-5). Factory reset clears them. If you get LTPDU status code 5, the light needs a factory reset.
- **Fresh lights need admin claim**: On a factory-reset light, use `session.post('sp/admin', admin_bytes)` before `session.post('sp/ss', ...)`. Use POST (create), not PUT (update) — PUT returns code 6 (unauthorized).
- **Switch BLE timing**: The switch only advertises BLE for ~30 seconds after a button press. You must press the button, then immediately run the BLE script.
- **macOS BLE caching**: Run `sudo pkill bluetoothd` between BLE sessions if connections fail.
- **Token length**: Tokens are exactly 14 bytes (28 hex chars). The raw frame has a 2-byte trailer after the token — don't include it.

## BLE Protocol (Sense+ Switch - LTPDU v2)

The switch exposes BLE GATT service `6D2AE1C4-9AEA-11EA-BB37-0242AC130002`:

| Characteristic | UUID | Purpose |
|---------------|------|---------|
| ENCRYPTION_SETUP | `6D2ADFDA-...` | X25519 key exchange + auth |
| ENCRYPTED | `6D2ADDA0-...` | Encrypted LTPDU commands |
| UNENCRYPTED | `A9E0A2DE-...` | Unencrypted LTPDU |
| FIRMWARE_DATA | `0919921C-...` | OTA firmware data |
| FIRMWARE_CONTROL | `135634E6-...` | OTA firmware control |

### Authentication Flow

1. Write 32-byte X25519 public key to ENCRYPTION_SETUP
2. Read 32-byte device public key from ENCRYPTION_SETUP
3. Derive shared secret via X25519 scalar multiplication
4. Derive AES key: `SHA1(SALT + shared_secret)[:16]`
5. Derive AES IV: `SHA1(IV_SALT + shared_secret)[:16]`
6. Create a **SINGLE** AES-CTR cipher stream (see critical note below)
7. Encrypt pairing TLV `[0x03, len, setup_code_digits_ascii]`, write to ENCRYPTION_SETUP
8. Read encrypted response from ENCRYPTION_SETUP, decrypt with **the same stream**
9. Send LTPDU commands via ENCRYPTED characteristic, decrypt responses with **the same stream**

Encryption salts (NL65/Matter devices):
```
SALT    = bca9e39738e2611c25d243c985d3c592ccbee330e077b89d7978f5fc785cb5e8
IV_SALT = 41e2e9eb5e5fa56e800e346d8c2b600742eb49839626faecdc37fb94a3a3c202
```

Legacy salts (older devices): `AES-NL-OPENAPI-KEY` / `AES-NL-OPENAPI-IV`

### CRITICAL: Single Cipher Stream

The BLE protocol uses a **single shared AES-CTR keystream** for both directions. Create ONE `encryptor()` instance and use it for both encrypting outbound data AND decrypting inbound data. AES-CTR XOR is symmetric, so the same operation works both ways.

```python
# CORRECT — single stream for both directions
stream = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
encrypted_out = stream.update(plaintext_out)    # encrypt to send
plaintext_in  = stream.update(ciphertext_in)    # decrypt received (same stream!)

# WRONG — two separate streams will desynchronize and produce garbage
enc = Cipher(...).encryptor()
dec = Cipher(...).decryptor()  # BAD: separate counter state
```

Using two cipher instances (one encryptor + one decryptor) causes the counter states to diverge. The device expects a single shared keystream position that advances with every byte in both directions. Getting this wrong results in 1-byte error responses (0x45, 0xE4, etc.).

### LTPDU BLE Command Format

```
Tag 0x0001 (2B) + length (2B) + endpoint (UTF-8)
Tag 0x0004 (2B) + length=1 (2B) + method (0=GET, 1=POST)
Tag 0x0002 (2B) + length (2B) + value (for POST only)
```

Response: Tag 0x0001 (endpoint echo) + Tag 0x0003 (status byte + value)

### Connection Notes

- Switch only advertises BLE after a button press (sleeps otherwise)
- Only one BLE session per wake cycle — connection drops after ~4-5 LTPDU requests
- macOS may cache stale BLE state; run `sudo pkill bluetoothd` between sessions
- BLE scripts require macOS (use CoreBluetooth via PyObjC)

## UDP Protocol (Lights - LTPDU v3)

NL65 lights expose LTPDU v3 on UDP port 12566 (discovered via mDNS `_ltpdu._udp.local.`). This is a custom binary protocol, NOT CoAP.

### V3 Binary Framing

Request:
```
version     (1 byte)  = 0x01
messageType (1 byte)  = 0x01 (Request)
messageId   (2 bytes) = random
clientId    (2 bytes) = 0x0000 (assigned by device)
uriType     (1 byte)  = 1=Secure, 2=LTPDU, 3=Events, 4=Identify, 5=Info
method      (1 byte)  = from MethodType enum
dataLength  (4 bytes) = len(data)
data        (N bytes) = payload
```

### Authentication

SRP-6a (Secure Remote Password) handshake using the pairing code as password. After SRP, session is encrypted with ChaCha20-Poly1305. Implemented in `tools/ltpdu_v3.py`.

## ESPHome Component

Location: `components/litewave/`

### YAML Configuration

```yaml
litewave:
  channel: 26
  pan_id: 0x3411
  sniff: false
  groups:
    - id: kitchen
      on_sequence: 0x09
      on_token: "33251BDC2E9B24FEE258DACFC67D"
      off_sequence: 0x0B
      off_token: "B7822E281E6E298019CF6DDC6280"
```

### Build Notes

- Requires ESP-IDF framework (not Arduino)
- Uses raw `esp_ieee802154` API (no OpenThread)
- `esp_ieee802154_enable()` must be called before any other 802.15.4 API
- If OpenThread owns the radio, `enable()` returns error — detect and handle
- WiFi + 802.15.4 coexist with `CONFIG_ESP_COEX_SW_COEXIST_ENABLE`
- `sniff: true` blocks WiFi scanning — only for temporary token capture
- Light component restores state during setup(), calling send_on/send_off before Litewave is ready — guard with `ready_` flag

## ha-nanoleaf-ltpdu Patches

The [ha-nanoleaf-ltpdu](https://github.com/zackman0010/ha-nanoleaf-ltpdu) integration requires three patches for NL65 compatibility:

### 1. crypto.py — New encryption salts

Replace legacy salts with hex salts from APK:
```python
LABEL_KEY = bytes.fromhex("bca9e39738e2611c25d243c985d3c592ccbee330e077b89d7978f5fc785cb5e8")
LABEL_IV  = bytes.fromhex("41e2e9eb5e5fa56e800e346d8c2b600742eb49839626faecdc37fb94a3a3c202")
```

### 2. const.py / device.py — Correct port

```python
DEFAULT_PORT = 5653  # not 5683 (standard CoAP port)
```

### 3. device.py — Accept token echo as auth success

NL65 echoes the auth token back instead of returning a status TLV:
```python
records = tlv.describe(resp_plain)
status = next((r["value"] for r in records if r.get("tag") == "status"), None)
# NL65 downlights echo back the auth_token on success instead of a status TLV.
token_echo = next((r["value"] for r in records if r.get("tag") == "auth_token"), None)
if status is not None and status != 0:
    raise DeviceError(f"authentication failed: {records}")
if status is None and token_echo is None:
    raise DeviceError(f"authentication failed (no status or token): {records}")
```

## Tools

All tools are in `tools/`. See README files in `firmware/sniffer/` and `firmware/transmitter/` for firmware documentation.

| Tool | Purpose |
|------|---------|
| `capture_tokens.py` | Interactive ON/OFF token capture with ESPHome YAML output |
| `capture.py` | Raw 802.15.4 frame capture to PCAP/JSON |
| `capture_raw_frames.py` | Capture ALL raw 802.15.4 frames with full hex bytes for analysis |
| `lw_replay.py` | Replay captured tokens via transmitter firmware |
| `ble_write_ss.py` | Write shared secret to Sense+ switch via BLE (uses bleak, cross-platform) |
| `ble_set_secret.py` | Legacy BLE secret writer (macOS CoreBluetooth/PyObjC — use `ble_write_ss.py` instead) |
| `ble_sense_ltpdu.py` | Read/write switch config endpoints via BLE (macOS) |
| `ble_scan_all.py` | Scan all nearby BLE devices (macOS) |
| `ltpdu_v3.py` | LTPDU v3 protocol library (SRP-6a + encrypted session) |
| `provision_v3.py` | Provision lights with shared secret via LTPDU v3 |
| `json_to_pcap.py` | Convert JSON captures to Wireshark PCAP |

## Firmware

### Sniffer (`tools/firmware/sniffer/`)

ESP-IDF firmware for ESP32-C6. Captures all 802.15.4 frames in promiscuous mode and outputs via USB serial using a binary framing protocol:

```
0xAA (sync) + LEN (1B) + CH (1B) + RSSI (1B) + LQI (1B) + DATA (LEN-3 bytes) + CHK (XOR)
```

Default: channel 26, locked. Boot button toggles scanning mode (channels 11-26, 500ms dwell).

Flash: `esptool.py --chip esp32c6 -p /dev/cu.usbmodem1101 -b 460800 write_flash --flash_size 2MB 0x0 tools/firmware/sniffer/bootloader.bin 0x8000 tools/firmware/sniffer/partition-table.bin 0x10000 tools/firmware/sniffer/litewave_sniffer.bin`

### Transmitter (`tools/firmware/transmitter/`)

ESP-IDF firmware for ESP32-C6. Receives 802.15.4 frames over USB serial and transmits them. Used by `lw_replay.py`.

Flash: `esptool.py --chip esp32c6 -p /dev/cu.usbmodem1101 -b 460800 write_flash --flash_size 2MB 0x0 tools/firmware/transmitter/bootloader.bin 0x8000 tools/firmware/transmitter/partition-table.bin 0x10000 tools/firmware/transmitter/litewave_tx.bin`

Both firmwares are built for ESP32-C6 with 2MB flash (must use `--flash_size 2MB`, not 8MB).
