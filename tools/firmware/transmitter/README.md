# Litewave Transmitter Firmware

ESP-IDF firmware for ESP32-C6 that receives 802.15.4 frames over USB serial and transmits them over the air. Used by `tools/lw_replay.py` to replay captured Litewave commands.

## Behaviour

- Listens on USB CDC serial for framed packets
- Transmits each received frame on the configured channel (default: 26)
- PAN ID, channel, and TX power are configured at boot

## Flashing

```bash
esptool.py --chip esp32c6 -p /dev/cu.usbmodem1101 -b 460800 \
  --before default_reset --after hard_reset \
  write_flash --flash_mode dio --flash_freq 80m --flash_size 2MB \
  0x0 bootloader.bin \
  0x10000 litewave_tx.bin \
  0x8000 partition-table.bin
```

**Important**: Use `--flash_size 2MB` (not 8MB).

## Building from Source

Requires ESP-IDF v5.4 with ESP32-C6 support.

```bash
source ~/esp/esp-idf/export.sh
cd firmware/transmitter
cmake --build build
```

## Files

- `main.c` — firmware source
- `sdkconfig` — ESP-IDF configuration
- `litewave_tx.bin` — pre-built application binary
- `bootloader.bin` — pre-built bootloader
- `partition-table.bin` — pre-built partition table
