#pragma once

#include <vector>
#include <cstring>
#include "esphome/core/component.h"
#include "esphome/core/log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_ieee802154.h"

namespace esphome {
namespace litewave {

static const uint8_t LITEWAVE_FCF_LO = 0x01;
static const uint8_t LITEWAVE_FCF_HI = 0x18;
static const uint16_t LITEWAVE_DST_MULTICAST = 0xFFF0;
static const uint8_t LITEWAVE_TOKEN_LEN = 14;
static const uint8_t LITEWAVE_TX_REPEATS = 5;
static const uint8_t LITEWAVE_TX_DELAY_MS = 20;
static const uint8_t LITEWAVE_MAX_FRAME_LEN = 127;

struct RxFrame {
    uint8_t data[LITEWAVE_MAX_FRAME_LEN];
    uint8_t len;
    int8_t rssi;
    uint8_t lqi;
};

class LitewaveGroup {
 public:
    void set_on_sequence(uint8_t seq) { on_seq_ = seq; }
    void set_on_token(const uint8_t token[LITEWAVE_TOKEN_LEN]) { memcpy(on_token_, token, LITEWAVE_TOKEN_LEN); }
    void set_off_sequence(uint8_t seq) { off_seq_ = seq; }
    void set_off_token(const uint8_t token[LITEWAVE_TOKEN_LEN]) { memcpy(off_token_, token, LITEWAVE_TOKEN_LEN); }

    uint8_t get_on_sequence() const { return on_seq_; }
    const uint8_t *get_on_token() const { return on_token_; }
    uint8_t get_off_sequence() const { return off_seq_; }
    const uint8_t *get_off_token() const { return off_token_; }

 protected:
    uint8_t on_seq_{0};
    uint8_t on_token_[LITEWAVE_TOKEN_LEN]{};
    uint8_t off_seq_{0};
    uint8_t off_token_[LITEWAVE_TOKEN_LEN]{};
};

class LitewaveComponent : public Component {
 public:
    void setup() override;
    void loop() override;
    void dump_config() override;
    float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

    void set_channel(uint8_t ch) { channel_ = ch; }
    void set_pan_id(uint16_t pan) { pan_id_ = pan; }
    void set_sniff(bool sniff) { sniff_ = sniff; }
    void add_group(LitewaveGroup *group) { groups_.push_back(group); }

    void send_on(LitewaveGroup *group);
    void send_off(LitewaveGroup *group);

    // Called from ISR context via C callback trampolines
    void on_tx_done(bool success);
    void on_rx_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info);

 protected:
    void transmit_command(uint8_t seq, const uint8_t *token);
    bool transmit_frame(const uint8_t *frame_data, uint8_t frame_len);
    void build_litewave_frame(uint8_t *buf, uint8_t *len, uint8_t seq, uint16_t dst, const uint8_t *token);
    void start_receive();
    void process_rx_frame(const RxFrame &frame);

    uint8_t channel_{26};
    uint16_t pan_id_{0x3B71};
    bool sniff_{false};
    bool has_openthread_{false};
    bool ready_{false};
    std::vector<LitewaveGroup *> groups_;

    SemaphoreHandle_t tx_sem_{nullptr};
    QueueHandle_t rx_queue_{nullptr};
    volatile bool tx_ok_{false};
};

}  // namespace litewave
}  // namespace esphome
