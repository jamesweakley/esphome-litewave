#include "litewave.h"

namespace esphome {
namespace litewave {

static const char *const TAG = "litewave";

static LitewaveComponent *g_litewave = nullptr;

// Weak callbacks: if OpenThread is linked, its strong definitions win.
// If no OpenThread, these provide the callback implementation.
extern "C" {

__attribute__((weak))
void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack,
                                   esp_ieee802154_frame_info_t *ack_frame_info) {
    if (g_litewave) g_litewave->on_tx_done(true);
}

__attribute__((weak))
void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) {
    if (g_litewave) g_litewave->on_tx_done(false);
}

__attribute__((weak))
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info) {
    if (g_litewave) {
        g_litewave->on_rx_done(frame, frame_info);
    } else {
        esp_ieee802154_receive_handle_done(frame);
    }
}

__attribute__((weak)) void esp_ieee802154_receive_failed(uint16_t error) {}
__attribute__((weak)) void esp_ieee802154_transmit_sfd_done(uint8_t *frame) {}
__attribute__((weak)) void esp_ieee802154_receive_sfd_done(void) {}
__attribute__((weak)) void esp_ieee802154_ed_done(int8_t power) {}
__attribute__((weak)) void esp_ieee802154_energy_detect_done(int8_t power) {}

}  // extern "C"

void LitewaveComponent::setup() {
    g_litewave = this;
    tx_sem_ = xSemaphoreCreateBinary();
    rx_queue_ = xQueueCreate(16, sizeof(RxFrame));

    // Try to initialize the 802.15.4 radio. If it fails, OpenThread
    // already owns the radio and we piggyback on it for TX.
    esp_err_t err = esp_ieee802154_enable();
    if (err == ESP_OK) {
        has_openthread_ = false;
        esp_ieee802154_set_channel(channel_);
        esp_ieee802154_set_txpower(20);
        esp_ieee802154_set_promiscuous(true);
        esp_ieee802154_set_rx_when_idle(sniff_);
        ESP_LOGI(TAG, "Standalone mode, channel %d", channel_);
    } else {
        has_openthread_ = true;
        ESP_LOGI(TAG, "OpenThread detected (enable returned %d), using coexistence mode", err);
    }

    if (sniff_ && has_openthread_) {
        ESP_LOGW(TAG, "Sniff mode not supported with OpenThread, disabling");
        sniff_ = false;
    }

    if (sniff_) {
        ESP_LOGI(TAG, "Sniff mode enabled on channel %d, PAN 0x%04X", channel_, pan_id_);
        ESP_LOGI(TAG, "Press Sense+ buttons and check logs for tokens");
        start_receive();
    }

    ready_ = true;
    ESP_LOGI(TAG, "Initialized on channel %d, PAN 0x%04X, %d groups", channel_, pan_id_, groups_.size());
}

void LitewaveComponent::loop() {
    if (!sniff_) return;

    RxFrame frame;
    while (xQueueReceive(rx_queue_, &frame, 0) == pdTRUE) {
        process_rx_frame(frame);
    }
}

void LitewaveComponent::dump_config() {
    ESP_LOGCONFIG(TAG, "Litewave:");
    ESP_LOGCONFIG(TAG, "  Channel: %d", channel_);
    ESP_LOGCONFIG(TAG, "  PAN ID: 0x%04X", pan_id_);
    ESP_LOGCONFIG(TAG, "  Sniff: %s", sniff_ ? "true" : "false");
    ESP_LOGCONFIG(TAG, "  OpenThread coexistence: %s", has_openthread_ ? "yes" : "no");
    ESP_LOGCONFIG(TAG, "  Groups: %d", groups_.size());
    for (auto *group : groups_) {
        char token_hex[29];
        for (int i = 0; i < LITEWAVE_TOKEN_LEN; i++) {
            sprintf(&token_hex[i * 2], "%02X", group->get_on_token()[i]);
        }
        ESP_LOGCONFIG(TAG, "    ON token=%s", token_hex);
    }
}

void LitewaveComponent::send_on(LitewaveGroup *group) {
    ESP_LOGI(TAG, "Sending ON");
    transmit_command(group->get_on_token());
}

void LitewaveComponent::send_off(LitewaveGroup *group) {
    ESP_LOGI(TAG, "Sending OFF");
    transmit_command(group->get_off_token());
}

void LitewaveComponent::build_litewave_frame(uint8_t *buf, uint8_t *len,
                                               uint16_t dst,
                                               const uint8_t *token) {
    uint8_t i = 0;
    buf[i++] = LITEWAVE_FCF_LO;
    buf[i++] = LITEWAVE_FCF_HI;
    buf[i++] = seq_++;
    buf[i++] = pan_id_ & 0xFF;
    buf[i++] = (pan_id_ >> 8) & 0xFF;
    buf[i++] = dst & 0xFF;
    buf[i++] = (dst >> 8) & 0xFF;
    buf[i++] = 0x09;  // TTL
    buf[i++] = 0x00;  // Command type
    memcpy(&buf[i], token, LITEWAVE_TOKEN_LEN);
    i += LITEWAVE_TOKEN_LEN;
    buf[i++] = 0xAE;  // Trailing byte 1
    buf[i++] = 0x09;  // Trailing byte 2
    *len = i;
}

void LitewaveComponent::transmit_command(const uint8_t *token) {
    if (!ready_) {
        ESP_LOGW(TAG, "Ignoring transmit before setup complete");
        return;
    }
    uint8_t frame[32];
    uint8_t frame_len;
    build_litewave_frame(frame, &frame_len, LITEWAVE_DST_MULTICAST, token);

    uint8_t saved_channel = 0;
    if (has_openthread_) {
        saved_channel = esp_ieee802154_get_channel();
        if (saved_channel != channel_) {
            esp_ieee802154_set_channel(channel_);
        }
    } else {
        esp_ieee802154_set_channel(channel_);
    }

    for (int r = 0; r < LITEWAVE_TX_REPEATS; r++) {
        bool ok = transmit_frame(frame, frame_len);
        ESP_LOGD(TAG, "TX repeat %d/%d: %s", r + 1, LITEWAVE_TX_REPEATS, ok ? "ok" : "FAILED");
        if (r < LITEWAVE_TX_REPEATS - 1) {
            vTaskDelay(pdMS_TO_TICKS(LITEWAVE_TX_DELAY_MS));
        }
    }

    if (has_openthread_) {
        if (saved_channel != 0 && saved_channel != channel_) {
            esp_ieee802154_set_channel(saved_channel);
        }
        esp_ieee802154_receive();
    } else if (sniff_) {
        start_receive();
    }
}

bool LitewaveComponent::transmit_frame(const uint8_t *frame_data, uint8_t frame_len) {
    uint8_t tx_buf[LITEWAVE_MAX_FRAME_LEN + 1];
    tx_buf[0] = frame_len;
    memcpy(&tx_buf[1], frame_data, frame_len);

    if (has_openthread_) {
        // OpenThread owns the callbacks, so fire-and-forget with a fixed wait.
        esp_err_t err = esp_ieee802154_transmit(tx_buf, false);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "esp_ieee802154_transmit failed: %d", err);
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(5));
        return true;
    }

    // Standalone mode: use semaphore callback.
    tx_ok_ = false;
    esp_err_t err = esp_ieee802154_transmit(tx_buf, false);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_ieee802154_transmit failed: %d", err);
        return false;
    }

    if (xSemaphoreTake(tx_sem_, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "TX timeout");
        return false;
    }
    return tx_ok_;
}

void LitewaveComponent::on_tx_done(bool success) {
    tx_ok_ = success;
    xSemaphoreGiveFromISR(tx_sem_, nullptr);
}

void LitewaveComponent::start_receive() {
    esp_ieee802154_set_channel(channel_);
    esp_ieee802154_receive();
}

void LitewaveComponent::on_rx_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info) {
    uint8_t frame_len = frame[0];
    if (frame_len > 0 && frame_len <= LITEWAVE_MAX_FRAME_LEN && sniff_) {
        RxFrame rx;
        rx.len = frame_len;
        memcpy(rx.data, &frame[1], frame_len);
        rx.rssi = frame_info->rssi;
        rx.lqi = frame_info->lqi;
        xQueueSendFromISR(rx_queue_, &rx, nullptr);
    }
    esp_ieee802154_receive_handle_done(frame);
}

void LitewaveComponent::process_rx_frame(const RxFrame &frame) {
    if (frame.len < 25) return;
    if (frame.data[0] != LITEWAVE_FCF_LO || frame.data[1] != LITEWAVE_FCF_HI) return;

    uint16_t pan = frame.data[3] | (frame.data[4] << 8);
    if (pan != pan_id_) return;

    uint16_t dst = frame.data[5] | (frame.data[6] << 8);
    if (dst != LITEWAVE_DST_MULTICAST) return;

    const uint8_t *payload = &frame.data[7];
    uint8_t payload_len = frame.len - 7;

    if (payload_len != 18 || payload[1] != 0x00) return;

    uint8_t ttl = payload[0];
    if (ttl != 0x09) return;

    uint8_t seq = frame.data[2];
    const uint8_t *token = &payload[2];

    char token_hex[29];
    for (int i = 0; i < LITEWAVE_TOKEN_LEN; i++) {
        sprintf(&token_hex[i * 2], "%02X", token[i]);
    }

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "=== Litewave command captured (rssi=%d) ===", frame.rssi);
    ESP_LOGI(TAG, "  token: \"%s\"", token_hex);
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Add to your YAML group config:");
    ESP_LOGI(TAG, "  on_token: \"%s\"   # if this was an ON press", token_hex);
    ESP_LOGI(TAG, "  off_token: \"%s\"  # if this was an OFF press", token_hex);
    ESP_LOGI(TAG, "===");
}

}  // namespace litewave
}  // namespace esphome
