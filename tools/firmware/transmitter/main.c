/*
 * Litewave Replay Transmitter -- ESP32-C6
 *
 * Receives commands over USB serial and transmits raw 802.15.4 frames.
 *
 * Serial protocol (host -> device):
 *   0xBB  sync byte
 *   LEN   frame length (1 byte, length of DATA)
 *   CH    channel (1 byte, 11-26)
 *   RPT   repeat count (1 byte, how many times to send)
 *   DLY   delay between repeats in ms (1 byte)
 *   DATA  raw 802.15.4 MAC frame (LEN bytes)
 *   CHK   XOR of all bytes from LEN through DATA
 *
 * Device -> host responses:
 *   "OK\n"    frame transmitted
 *   "ERR:...\n" error
 */

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_ieee802154.h"
#include "esp_timer.h"
#include "esp_log.h"

#define SYNC_BYTE       0xBB
#define MAX_FRAME_LEN   127

static SemaphoreHandle_t s_tx_done;
static volatile bool s_tx_ok;

void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack,
                                   esp_ieee802154_frame_info_t *ack_frame_info)
{
    s_tx_ok = true;
    xSemaphoreGive(s_tx_done);
}

void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error)
{
    s_tx_ok = false;
    xSemaphoreGive(s_tx_done);
}

/* Required stubs */
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info)
{
    esp_ieee802154_receive_handle_done(frame);
}
void esp_ieee802154_receive_failed(uint16_t error) { }
void esp_ieee802154_transmit_sfd_done(uint8_t *frame) { }
void esp_ieee802154_receive_sfd_done(void) { }
void esp_ieee802154_ed_done(int8_t power) { }
void esp_ieee802154_energy_detect_done(int8_t power) { }

static int read_byte(void)
{
    int c;
    while ((c = getchar()) == EOF) {
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    return c & 0xFF;
}

static bool transmit_frame(uint8_t channel, const uint8_t *frame_data, uint8_t frame_len)
{
    /* The 802.15.4 driver expects: frame[0] = length, frame[1..N] = MPDU */
    uint8_t tx_buf[MAX_FRAME_LEN + 1];
    tx_buf[0] = frame_len;
    memcpy(&tx_buf[1], frame_data, frame_len);

    esp_ieee802154_set_channel(channel);

    s_tx_ok = false;
    esp_err_t err = esp_ieee802154_transmit(tx_buf, false); /* false = no CCA */
    if (err != ESP_OK) {
        return false;
    }

    /* Wait for TX done callback */
    if (xSemaphoreTake(s_tx_done, pdMS_TO_TICKS(100)) != pdTRUE) {
        return false;
    }

    return s_tx_ok;
}

void app_main(void)
{
    s_tx_done = xSemaphoreCreateBinary();

    /* Initialize 802.15.4 radio */
    esp_ieee802154_enable();
    esp_ieee802154_set_promiscuous(true);
    esp_ieee802154_set_rx_when_idle(false);
    esp_ieee802154_set_txpower(20); /* max TX power */

    printf("LITEWAVE_TX_READY\n");
    fflush(stdout);

    while (1) {
        /* Wait for sync byte */
        int b = read_byte();
        if (b != SYNC_BYTE) {
            continue;
        }

        /* Read header */
        uint8_t frame_len = read_byte();
        uint8_t channel = read_byte();
        uint8_t repeats = read_byte();
        uint8_t delay_ms = read_byte();

        if (frame_len == 0 || frame_len > MAX_FRAME_LEN || channel < 11 || channel > 26) {
            printf("ERR:BAD_PARAMS len=%d ch=%d\n", frame_len, channel);
            fflush(stdout);
            continue;
        }

        /* Read frame data */
        uint8_t frame_data[MAX_FRAME_LEN];
        uint8_t chk = frame_len ^ channel ^ repeats ^ delay_ms;
        for (int i = 0; i < frame_len; i++) {
            frame_data[i] = read_byte();
            chk ^= frame_data[i];
        }

        /* Read and verify checksum */
        uint8_t rx_chk = read_byte();
        if (chk != rx_chk) {
            printf("ERR:CHECKSUM expected=0x%02X got=0x%02X\n", chk, rx_chk);
            fflush(stdout);
            continue;
        }

        /* Transmit with repeats */
        int ok_count = 0;
        for (int r = 0; r < repeats; r++) {
            if (transmit_frame(channel, frame_data, frame_len)) {
                ok_count++;
            }
            if (r < repeats - 1 && delay_ms > 0) {
                vTaskDelay(pdMS_TO_TICKS(delay_ms));
            }
        }

        printf("OK:%d/%d\n", ok_count, repeats);
        fflush(stdout);
    }
}
