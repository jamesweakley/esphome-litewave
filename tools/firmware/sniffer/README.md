# Litewave Sniffer Firmware

ESP-IDF firmware for ESP32-C6 that captures IEEE 802.15.4 frames in promiscuous mode and outputs them over USB serial.

## Behaviour

- Starts in **locked mode** on channel 26 (Litewave default)
- Press the boot button to toggle **scanning mode** (cycles channels 11-26 with 500ms dwell)
- Outputs binary-framed packets over USB CDC serial at 115200 baud

## Serial Framing Protocol

Each captured frame is sent as:

```
0xAA          sync byte
LEN           1 byte: total bytes after LEN up to (not including) checksum
CH            1 byte: channel number (11-26)
RSSI          1 byte: signed int8
LQI           1 byte: uint8
DATA          LEN-3 bytes: raw 802.15.4 MPDU (MAC header + payload + FCS)
CHK           1 byte: XOR of all bytes from LEN through DATA
```

## Flashing

Requires `esptool.py` (part of ESP-IDF or installable via `pip install esptool`).

```bash
esptool.py --chip esp32c6 -p /dev/cu.usbmodem1101 -b 460800 \
  --before default_reset --after hard_reset \
  write_flash --flash_mode dio --flash_freq 80m --flash_size 2MB \
  0x0 bootloader.bin \
  0x10000 litewave_sniffer.bin \
  0x8000 partition-table.bin
```

**Important**: Use `--flash_size 2MB` (not 8MB). Incorrect flash size causes a boot crash (`assert failed: __esp_system_init_fn_init_flash`).

## Building from Source

Requires ESP-IDF v5.4 with ESP32-C6 support.

```bash
source ~/esp/esp-idf/export.sh
cd firmware/sniffer
cmake --build build
```

## Files

- `main.c` — firmware source
- `sdkconfig` — ESP-IDF configuration
- `litewave_sniffer.bin` — pre-built application binary
- `bootloader.bin` — pre-built bootloader
- `partition-table.bin` — pre-built partition table
