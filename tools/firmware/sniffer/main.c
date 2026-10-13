/*
 * Litewave 802.15.4 Sniffer — ESP32-C6
 *
 * Promiscuous-mode capture with channel scanning.
 * Streams raw frames over USB serial for host-side analysis.
 *
 * Serial protocol (per frame):
 *   0xAA  sync
 *   LEN   total bytes after LEN up to (not including) checksum (1 byte)
 *   CH    channel 11-26 (1 byte)
 *   RSSI  signed int8 (1 byte)
 *   LQI   uint8 (1 byte)
 *   DATA  raw 802.15.4 frame (LEN-3 bytes)
 *   CHK   XOR of all bytes from LEN through DATA
 */

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_ieee802154.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include "esp_log.h"

#define SYNC_BYTE       0xAA
#define MAX_FRAME_LEN   127
#define QUEUE_SIZE      32
#define BOOT_BUTTON     GPIO_NUM_9

/* Channel scanning config */
#define CH_MIN          11
#define CH_MAX          26
#define SCAN_DWELL_MS   500   /* ms per channel in scan mode */

typedef enum {
    MODE_SCAN,      /* hop through all channels */
    MODE_LOCKED,    /* stay on one channel */
} sniffer_mode_t;

typedef struct {
    uint8_t  data[MAX_FRAME_LEN];
    uint8_t  len;
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  lqi;
} rx_frame_t;

static QueueHandle_t s_rx_queue;
static volatile sniffer_mode_t s_mode = MODE_LOCKED;
static volatile uint8_t s_current_channel = 26;
static volatile uint8_t s_locked_channel = 26;
static volatile uint32_t s_frame_counts[27]; /* index by channel */

/* ISR callback — called from 802.15.4 driver when a frame is received */
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info)
{
    /*
     * frame[0] = frame length (802.15.4 PHR)
     * frame[1..frame[0]] = MPDU (MAC header + payload + FCS)
     */
    uint8_t frame_len = frame[0];
    if (frame_len > MAX_FRAME_LEN || frame_len == 0) {
        esp_ieee802154_receive_handle_done(frame);
        return;
    }

    rx_frame_t rx;
    rx.len = frame_len;
    memcpy(rx.data, &frame[1], frame_len);
    rx.channel = s_current_channel;
    rx.rssi = frame_info->rssi;
    rx.lqi = frame_info->lqi;

    /* Non-blocking enqueue from ISR context */
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xQueueSendFromISR(s_rx_queue, &rx, &xHigherPriorityTaskWoken);

    s_frame_counts[rx.channel]++;

    /* Must call this to release the frame buffer */
    esp_ieee802154_receive_handle_done(frame);

    if (xHigherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }
}

/* Required stubs for the 802.15.4 driver */
void esp_ieee802154_receive_failed(uint16_t error) { }
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_frame_info) { }
void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) { }
void esp_ieee802154_transmit_sfd_done(uint8_t *frame) { }
void esp_ieee802154_receive_sfd_done(void) { }
void esp_ieee802154_ed_done(int8_t power) { }
void esp_ieee802154_energy_detect_done(int8_t power) { }

static void send_heartbeat(void)
{
    /*
     * Heartbeat packet:
     *   0xAA (sync)
     *   total_len = 11 (CH + RSSI + LQI + 8 data bytes)
     *   CH = 0 (status / heartbeat indicator)
     *   RSSI = s_current_channel (channel number 11-26)
     *   LQI = s_mode (0 = locked, 1 = scan)
     *   DATA = "LWSNIFF\0" (8 bytes)
     *   CHK = XOR checksum
     */
    static const uint8_t hb_data[8] = {'L', 'W', 'S', 'N', 'I', 'F', 'F', '\0'};
    uint8_t total_len = 3 + sizeof(hb_data);
    uint8_t chk = total_len;

    putchar(SYNC_BYTE);
    putchar(total_len);

    uint8_t ch = 0; /* 0 indicates status/heartbeat */
    chk ^= ch;
    putchar(ch);

    int8_t ch_info = (int8_t)s_current_channel;
    chk ^= (uint8_t)ch_info;
    putchar((uint8_t)ch_info);

    uint8_t mode_info = (uint8_t)s_mode;
    chk ^= mode_info;
    putchar(mode_info);

    for (size_t i = 0; i < sizeof(hb_data); i++) {
        chk ^= hb_data[i];
        putchar(hb_data[i]);
    }

    putchar(chk);
    fflush(stdout);
}

static void send_frame_to_host(const rx_frame_t *rx)
{
    /* Build serial packet: SYNC LEN CH RSSI LQI DATA CHK */
    uint8_t meta_len = 3; /* CH + RSSI + LQI */
    uint8_t total_len = meta_len + rx->len;

    uint8_t chk = total_len;
    putchar(SYNC_BYTE);
    putchar(total_len);

    chk ^= rx->channel;
    putchar(rx->channel);

    chk ^= (uint8_t)rx->rssi;
    putchar((uint8_t)rx->rssi);

    chk ^= rx->lqi;
    putchar(rx->lqi);

    for (int i = 0; i < rx->len; i++) {
        chk ^= rx->data[i];
        putchar(rx->data[i]);
    }

    putchar(chk);
    fflush(stdout);
}

static void set_channel(uint8_t ch)
{
    s_current_channel = ch;
    esp_ieee802154_set_channel(ch);
    esp_ieee802154_receive();
}

/* Channel scan timer callback */
static void scan_timer_cb(void *arg)
{
    if (s_mode != MODE_SCAN) return;

    uint8_t next = s_current_channel + 1;
    if (next > CH_MAX) next = CH_MIN;
    set_channel(next);
}

static void boot_button_task(void *arg)
{
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << BOOT_BUTTON),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);

    bool last_pressed = false;

    while (1) {
        bool pressed = (gpio_get_level(BOOT_BUTTON) == 0);

        if (pressed && !last_pressed) {
            if (s_mode == MODE_SCAN) {
                /* Lock to current channel */
                s_mode = MODE_LOCKED;
                s_locked_channel = s_current_channel;
                /* Send a status message as a "frame" with channel=0 to indicate lock */
            } else {
                /* Cycle locked channel, or go back to scan */
                if (s_locked_channel >= CH_MAX) {
                    s_mode = MODE_SCAN;
                } else {
                    s_locked_channel++;
                    set_channel(s_locked_channel);
                }
            }
        }
        last_pressed = pressed;
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

/* Heartbeat timer callback (every 1 second) */
static void heartbeat_timer_cb(void *arg)
{
    send_heartbeat();
}

static void serial_rx_task(void *arg)
{
    while (1) {
        int c = getchar();
        if (c != EOF) {
            /* Any probe from host triggers immediate heartbeat */
            if (c == SYNC_BYTE || c == '?' || c == 'p' || c == 'h' || c == '\n') {
                send_heartbeat();
            }
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

void app_main(void)
{
    s_rx_queue = xQueueCreate(QUEUE_SIZE, sizeof(rx_frame_t));

    /* Initialize 802.15.4 radio */
    esp_ieee802154_enable();
    esp_ieee802154_set_promiscuous(true);
    esp_ieee802154_set_rx_when_idle(true);

    /* Start locked on channel 26 (known Litewave channel) */
    set_channel(s_locked_channel);

    /* Channel scan timer */
    esp_timer_handle_t scan_timer;
    esp_timer_create_args_t timer_args = {
        .callback = scan_timer_cb,
        .name = "scan",
    };
    esp_timer_create(&timer_args, &scan_timer);
    esp_timer_start_periodic(scan_timer, SCAN_DWELL_MS * 1000);

    /* Heartbeat timer (1 second interval) */
    esp_timer_handle_t hb_timer;
    esp_timer_create_args_t hb_timer_args = {
        .callback = heartbeat_timer_cb,
        .name = "hb",
    };
    esp_timer_create(&hb_timer_args, &hb_timer);
    esp_timer_start_periodic(hb_timer, 1000 * 1000);

    /* Send initial heartbeat immediately on startup */
    send_heartbeat();

    /* Serial RX task for instant host probe responses */
    xTaskCreate(serial_rx_task, "serial_rx", 2048, NULL, 5, NULL);

    /* Boot button handler */
    xTaskCreate(boot_button_task, "btn", 2048, NULL, 5, NULL);

    /* Main loop: dequeue and send frames to host */
    rx_frame_t rx;
    while (1) {
        if (xQueueReceive(s_rx_queue, &rx, pdMS_TO_TICKS(100)) == pdTRUE) {
            send_frame_to_host(&rx);
        }
    }
}
