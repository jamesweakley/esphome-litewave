# esphome-litewave

ESPHome external component for controlling Nanoleaf lights via the Litewave protocol over raw IEEE 802.15.4.

Works on ESP32-C6 and ESP32-H2 (any ESP32 with an 802.15.4 radio). Connects to Home Assistant over WiFi and sends Litewave commands directly to Nanoleaf downlights, bulbs, and strips — no Sense+ switch needed after initial token capture.

## Requirements

- ESP32-C6 or ESP32-H2 board
- ESPHome with ESP-IDF framework
- Nanoleaf lights in a Litewave control group (set up via the Nanoleaf app + Sense+ switch)
- The Sense+ switch for one-time token capture

## Quick Start

### 1. Set up the control group

In the Nanoleaf app, create a control group and add your lights. For reliable setup, pair lights with Matter (Home Assistant) first, then add them to the Nanoleaf app.

### 2. Capture tokens

Add the component to your ESPHome config with sniff mode enabled:

```yaml
external_components:
  - source: github://jamesweakley/esphome-litewave

litewave:
  channel: 26
  pan_id: 0x3B71
  sniff: true
```

Flash, then press the Sense+ ON button. Check the ESPHome logs for:

```
[I][litewave]: === Litewave command captured (rssi=-68) ===
[I][litewave]:   sequence: 0xFB
[I][litewave]:   token: "949B16B63E32024A9DD73E03604D"
```

Press the OFF button and note that sequence + token too.

### 3. Configure groups

```yaml
litewave:
  channel: 26
  pan_id: 0x3B71
  sniff: false
  groups:
    - id: living_room
      on_sequence: 0xFB
      on_token: "949B16B63E32024A9DD73E03604D"
      off_sequence: 0xFD
      off_token: "9ACC50F8E109757695C384C4EA74"
```

### 4. Wire up actions

```yaml
light:
  - platform: binary
    name: "Living Room Lights"
    output: led_output
    id: living_room_light
    on_turn_on:
      - litewave.send_on:
          group: living_room
    on_turn_off:
      - litewave.send_off:
          group: living_room
```

## Configuration

### `litewave` component

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `channel` | int (11-26) | 26 | IEEE 802.15.4 channel |
| `pan_id` | hex uint16 | 0x3B71 | Litewave PAN ID |
| `sniff` | boolean | false | Enable promiscuous RX to capture tokens |
| `groups` | list | [] | List of control group definitions |

### Group config

| Key | Type | Description |
|-----|------|-------------|
| `id` | ID | Reference name for actions |
| `on_sequence` | hex uint8 | 802.15.4 sequence number for ON command |
| `on_token` | string | 14-byte hex token for ON command |
| `off_sequence` | hex uint8 | 802.15.4 sequence number for OFF command |
| `off_token` | string | 14-byte hex token for OFF command |

### Actions

- `litewave.send_on` — send the ON command for a group
- `litewave.send_off` — send the OFF command for a group

Both require `group:` parameter referencing a group ID.

## How it works

Nanoleaf Litewave is a proprietary protocol running on standard IEEE 802.15.4 radio. It uses unencrypted broadcast/multicast frames with pre-shared command tokens that are provisioned during control group setup. This component replays those tokens to control the lights.

Each command is sent as a 25-byte 802.15.4 data frame to the multicast address `0xFFF0` on the Litewave PAN, repeated 5 times for reliability. No acknowledgment is expected — it's fire-and-forget, same as the real Sense+ switch.

## Notes

- Tokens are per-control-group, not per-light. One capture covers all lights in a group.
- Tokens change if you remove/re-add lights to a control group. Recapture if you modify the group.
- The ESP32-C6 shares its 2.4 GHz radio between WiFi and 802.15.4. Brief Litewave TX bursts do not noticeably impact WiFi.
- The `sniff` option should be disabled in production to avoid unnecessary radio RX.
