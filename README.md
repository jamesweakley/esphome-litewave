# esphome-litewave

ESPHome external component for controlling Nanoleaf lights via the proprietary **Litewave protocol** over raw IEEE 802.15.4 broadcasts.

Works on **ESP32-C6** and **ESP32-H2** (or any ESP32 with an 802.15.4 radio). Sends instant Litewave commands directly to Nanoleaf Essentials Downlights (NL65), bulbs, and strips — working immediately on boot with zero WiFi or Thread dependency.

---

## Why use this? Home Assistant already supports Matter over Thread

You can use this in conjunction with Matter over Thread, getting the best of both worlds.

With Matter, you can control the lights from Home Assistant, set up automations, etc.

However, nothing beats Litewave when it comes to instant, direct light control. When using an ESP32-based light switch with this extension, there is zero other infrastructure involved. No Home Assistant server, no Wifi, no Thread mesh.

---

## How It Works: Cryptographic Room Isolation

Nanoleaf Sense+ switches and downlights authenticate commands using a 54-byte shared secret (`sp/ss`).

By assigning different shared secrets to different rooms (e.g. `0x01` for Living Room, `0x02` for Kitchen), lights in each room respond exclusively to their assigned room's tokens. This achieves **independent per-room control** across any number of rooms using only a single physical Sense+ switch during setup (or by reusing pre-cataloged token sets).

```
   ESP32-C6 / ESP32-H2 (ESPHome)
              │
              │  Raw 802.15.4 Broadcast (Channel 26, PAN 0x3411)
              ▼
   ┌───────────────────────┬───────────────────────┐
   │  Living Room (SS: 01) │   Kitchen (SS: 02)    │
   │  Responds to Room 1   │   Responds to Room 2  │
   │  Tokens only          │   Tokens only         │
   └───────────────────────┴───────────────────────┘
```

---

## Requirements

- **ESP32-C6** or **ESP32-H2** development board
- ESPHome with `framework: type: esp-idf`
- Python 3.9+ with tool requirements installed:
  ```bash
  pip install -r tools/requirements.txt
  ```

---

## Setup Workflow

Setting up a room consists of three simple steps:

### Step 1: Obtain Tokens & Shared Secret

Choose one of two approaches:

#### Option A: Use the Pre-Generated Token Catalog (No Switch Needed)
Pick an entry from [`token_catalog.yaml`](token_catalog.yaml). Each entry contains a deterministic shared secret (e.g. `0x00`, `0x01`, `0x02`...) and pre-captured ON, OFF, DIM+, and DIM- tokens.

#### Option B: Capture Custom Tokens with a Sense+ Switch
Run the unified capture CLI tool. It writes your chosen shared secret to the Sense+ switch via BLE and captures all 4 button presses through the ESP32-C6 sniffer:

```bash
# 1. Put switch in BLE pairing mode: hold ON + OFF for 3 seconds (white LED flashes)
# 2. Run capture tool:
./tools/capture_and_provision.py \
    --switch-name "Nanoleaf Wireless SW 123" \
    --switch-code "1234-567-abcd" \
    --secret 0x01 \
    --group-name living_room
```

*(Note: If the ESP32 currently has transmitter firmware flashed, the tool will automatically offer to flash the sniffer firmware for you).*

---

### Step 2: Provision Lights with the Shared Secret

Push the shared secret to each light in the room using `tools/provision_v3.py`. Lights are discovered automatically via local mDNS.

Look at the back of each downlight for its **3-character hardware ID** (e.g. `789` or `1D9`):

#### Method 1: Cloud Token (Recommended)
Reuses existing authentication tokens from your Nanoleaf Cloud account and automatically authorizes all Sense+ switches found in your home:

```bash
# Set your Nanoleaf account credentials in environment (or pass via flags / prompt)
export NANOLEAF_EMAIL="user@example.com"
export NANOLEAF_PASSWORD="your_password"

# Provision light '789' with shared secret 0x01 (auto-discovers switch ACL from cloud):
python3 tools/provision_v3.py --id 789 --secret 0x01

# Provision multiple lights in the room at once:
python3 tools/provision_v3.py --id 789,1D9 --secret 0x01
```

#### Method 2: Matter Pairing Code (Fallback)
Uses the 11-digit Matter setup code printed on the light, and optionally authorizes a specific switch by EUI:

```bash
python3 tools/provision_v3.py \
    --session-method new_pairing \
    --id 789 \
    --code 1111-222-3333 \
    --switch-eui e406bffffaabbccc \
    --secret 0x01
```

#### Inspect Existing Configuration & ACL (Safe Read-Only)
```bash
python3 tools/provision_v3.py --id 789 --read-only
```

---

### Step 3: Configure ESPHome

Add the `litewave` component and group configuration to your ESPHome YAML:

```yaml
esphome:
  name: litewave-controller

esp32:
  variant: ESP32C6
  board: esp32-c6-devkitm-1
  framework:
    type: esp-idf

external_components:
  - source: github://jamesweakley/esphome-litewave
    components: [litewave]

litewave:
  channel: 26        # Your home radio channel (from nanoleaf_cloud.py or provision_v3.py)
  pan_id: 0x1234     # Your home 2-byte PAN ID (from nanoleaf_cloud.py or provision_v3.py)

  groups:
    - id: living_room
      switch_eui: "e406bffffed47797"  # 16-hex EUI-64 of the switch (used to configure light ACL)
      shared_secret: "0x01"           # auto zero-padded to 54 bytes, this is written to the lights and is what actually creates group isolation
      on_sequence: 0xFB
      on_token: "949B16B63E32024A9DD73E032211"
      off_sequence: 0xFD
      off_token: "9ACC50F8E209757295C384C4EA74"
      dim_plus_sequence: 0x03
      dim_plus_token: "08D15628B08D981A3F7CC3674681"
      dim_minus_sequence: 0x05
      dim_minus_token: "166BAA118582F3C3FF4D6B92298E"
      lights:
        - id: "789"                           # 3-char hardware ID, mDNS name, or EUI
          name: "Living Room DL 1"
          pairing_code: "1640-700-5590"
          # host: "192.168.1.50"              # Optional manual IP/host override

# Expose an interactive Provisioning Service to Home Assistant (Tools -> Actions):
api:
  services:
    - service: provision_light
      variables:
        light_id: string
        pairing_code: string
      then:
        - litewave.provision_light:
            light_id: !lambda "return light_id;"
            pairing_code: !lambda "return pairing_code;"

# Wire actions to physical buttons, Home Assistant entities, or automations:
binary_sensor:
  - platform: gpio
    pin:
      number: GPIO9
      mode:
        pullup: true
        input: true
      inverted: true
    name: "Wall Switch Button"
    on_press:
      - litewave.send_on:
          group: living_room
    on_double_click:
      - litewave.send_off:
          group: living_room

# Or trigger light provisioning directly via a static button:
button:
  - platform: template
    name: "Provision Living Room Light 1"
    on_press:
      - litewave.provision_light:
          light_id: "789"
```

---

## ESPHome Component Reference

### `litewave` Component Options

| Option | Type | Default | Description |
|---|---|---|---|
| `channel` | integer (11–26) | | 802.15.4 radio channel (Litewave default is 26) |
| `pan_id` | hex uint16 |  | Litewave PAN ID |
| `sniff` | boolean | `false` | Enable promiscuous RX packet sniffer in logs |
| `groups` | list | `[]` | List of room control group definitions |

### Group Schema

| Option | Type | Required | Description |
|---|---|---|---|
| `id` | ID | Yes | Group identifier for action calls |
| `switch_eui` | string (16-hex chars) | Optional | Switch EUI-64 address (e.g. `"e406bffffed47797"`), used to automatically build and write the light's switch ACL (`lb/0/sp/llc/acl`) during provisioning |
| `shared_secret` | string / hex | Optional | Shared secret (e.g. `"0x01"` or 108 hex chars). Auto-padded to 54 bytes. |
| `on_sequence` | hex uint8 | Yes | 802.15.4 sequence number for ON |
| `on_token` | hex string (28 chars) | Yes | 14-byte captured ON token |
| `off_sequence` | hex uint8 | Yes | 802.15.4 sequence number for OFF |
| `off_token` | hex string (28 chars) | Yes | 14-byte captured OFF token |
| `dim_plus_sequence` | hex uint8 | Optional | Sequence number for DIM+ (brightness up) |
| `dim_plus_token` | hex string (28 chars) | Optional | 14-byte captured DIM+ token |
| `dim_minus_sequence` | hex uint8 | Optional | Sequence number for DIM- (brightness down) |
| `dim_minus_token` | hex string (28 chars) | Optional | 14-byte captured DIM- token |
| `lights` | list | Optional | List of `{id, [pairing_code], [name], [host]}` for on-device provisioning |

### Available ESPHome Actions

- `litewave.send_on: group: <group_id>` — Transmits ON command burst
- `litewave.send_off: group: <group_id>` — Transmits OFF command burst
- `litewave.send_dim_plus: group: <group_id>` — Transmits DIM+ brightness up command burst
- `litewave.send_dim_minus: group: <group_id>` — Transmits DIM- brightness down command burst
- `litewave.provision_light: light_id: <light_id> [, pairing_code: <pairing_code>]` — Runs on-device SRP-6a provisioning over UDP to push the assigned group's `shared_secret` and switch ACL to the light (accepts templated lambdas).

---

## Alternative Component: `nanoleaf_wifi` (Wi-Fi Essentials & OpenAPI)

For **Matter-over-Wi-Fi** Nanoleaf devices that do not have an 802.15.4 / Thread radio (such as the **Nanoleaf Essentials WiFi A19 model `NL75K1`**, Holiday String Lights, and Wi-Fi Lightstrips), use the `nanoleaf_wifi` external component.

It provides direct local control from the ESP32 over your local Wi-Fi network without Home Assistant using:
1. **Local OpenAPI REST Client**: Discovers and pairs with devices by DNS/mDNS hostname (e.g. `nanoleaf-a19-3dc.local`).
2. **`extControl` UDP Streaming**: Streams unauthenticated binary RGB frames directly to UDP port `60222` with sub-10ms response time.

### `nanoleaf_wifi` YAML Configuration

```yaml
external_components:
  - source: github://jamesweakley/esphome-litewave
    components: [nanoleaf_wifi]

nanoleaf_wifi:
  lights:
    - id: bedroom_bulb
      host: "nanoleaf-a19-3dc.local"   # DNS / mDNS hostname
      port: 12566                     # OpenAPI HTTP port (default: 12566)
      udp_port: 60222                 # extControl UDP port (default: 60222)
      auth_token: "qs1G6uIl9MqGnyzQM9P9bBRVHiZq79wx"  # Saved auth token

button:
  # Activate / re-arm extControl mode (when auth_token is already known):
  - platform: template
    name: "Enable extControl Bedroom Bulb"
    on_press:
      - nanoleaf_wifi.enable_extcontrol:
          light_id: bedroom_bulb

  # One-time pairing / token acquisition (when pairing without token):
  - platform: template
    name: "Provision Bedroom Bulb"
    on_press:
      - nanoleaf_wifi.provision_light:
          light_id: bedroom_bulb

  # Direct, instant UDP control:
  - platform: template
    name: "Bedroom Bulb ON"
    on_press:
      - nanoleaf_wifi.send_on:
          light_id: bedroom_bulb
          red: 255
          green: 255
          blue: 255
          transition_ms: 100

  - platform: template
    name: "Bedroom Bulb OFF"
    on_press:
      - nanoleaf_wifi.send_off:
          light_id: bedroom_bulb
          transition_ms: 100

  - platform: template
    name: "Bedroom Bulb Warm White"
    on_press:
      - nanoleaf_wifi.set_color:
          light_id: bedroom_bulb
          red: 255
          green: 147
          blue: 41
          transition_ms: 200
```

### `nanoleaf_wifi` Setup & Usage Flow:
1. **Initial Pairing (if token is not known):** Tap **Connect to API** in the Nanoleaf App settings, then trigger `nanoleaf_wifi.provision_light` to fetch and log the permanent `auth_token`.
2. **Re-enabling extControl:** If your `auth_token` is already in YAML, simply call `nanoleaf_wifi.enable_extcontrol: light_id: bedroom_bulb` (or run it on boot) to ensure the bulb is powered on and streaming mode is active.
3. **Instant Control:** Once in `extControl` mode, all `send_on`, `send_off`, and `set_color` actions stream raw binary frames over UDP port 60222 peer-to-peer with zero latency.

---

## Tools Inventory

| Script | Purpose |
|---|---|
| `tools/capture_and_provision.py` | Unified CLI: scans switches, writes shared secret via BLE, captures 4 buttons from sniffer, and manages sniffer firmware. |
| `tools/provision_v3.py` | Provisions lights over mDNS using Cloud Tokens or Matter pairing codes. |
| `tools/generate_catalog.py` | Automated batch capture tool for generating 100 sequential token catalog entries. |
| `tools/nanoleaf_cloud.py` | Standalone CLI & module to query Nanoleaf Cloud API for device auth tokens. |
| `tools/lw_replay.py` | Command-line token replay utility for testing against the transmitter firmware. |
| `tools/firmware/sniffer/` | Pre-built binary and source for the ESP32-C6 promiscuous sniffer with 1s heartbeat. |
| `tools/firmware/transmitter/` | Pre-built binary and source for the ESP32-C6 serial replay transmitter. |

---

## License & Credits

Reverse engineering and ESPHome implementation by James Weakley.
Provided under the MIT License.
