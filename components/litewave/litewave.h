#pragma once

#include <vector>
#include <string>
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
static const uint8_t LITEWAVE_SHARED_SECRET_LEN = 54;

struct RxFrame {
    uint8_t data[LITEWAVE_MAX_FRAME_LEN];
    uint8_t len;
    int8_t rssi;
    uint8_t lqi;
};

struct LightInfo {
    std::string id;
    std::string name;
    std::string host;
    std::string pairing_code;
};

class LitewaveGroup {
 public:
    void set_on_sequence(uint8_t seq) { on_seq_ = seq; }
    void set_on_token(const uint8_t token[LITEWAVE_TOKEN_LEN]) { memcpy(on_token_, token, LITEWAVE_TOKEN_LEN); }
    void set_off_sequence(uint8_t seq) { off_seq_ = seq; }
    void set_off_token(const uint8_t token[LITEWAVE_TOKEN_LEN]) { memcpy(off_token_, token, LITEWAVE_TOKEN_LEN); }
    void set_dim_plus_sequence(uint8_t seq) { dim_plus_seq_ = seq; has_dim_plus_ = true; }
    void set_dim_plus_token(const uint8_t token[LITEWAVE_TOKEN_LEN]) { memcpy(dim_plus_token_, token, LITEWAVE_TOKEN_LEN); has_dim_plus_ = true; }
    void set_dim_minus_sequence(uint8_t seq) { dim_minus_seq_ = seq; has_dim_minus_ = true; }
    void set_dim_minus_token(const uint8_t token[LITEWAVE_TOKEN_LEN]) { memcpy(dim_minus_token_, token, LITEWAVE_TOKEN_LEN); has_dim_minus_ = true; }
    void set_dst(uint16_t dst) { dst_ = dst; }

    void set_shared_secret(const uint8_t *ss, size_t len) {
        size_t copy_len = len < LITEWAVE_SHARED_SECRET_LEN ? len : LITEWAVE_SHARED_SECRET_LEN;
        memcpy(shared_secret_, ss, copy_len);
        shared_secret_len_ = copy_len;
    }

    void set_acl_payload(const uint8_t *acl, size_t len) {
        size_t copy_len = len < sizeof(acl_payload_) ? len : sizeof(acl_payload_);
        memcpy(acl_payload_, acl, copy_len);
        acl_len_ = copy_len;
    }

    void set_switch_eui(const std::string &eui) { switch_eui_ = eui; }

    void add_light(const LightInfo &light) { lights_.push_back(light); }

    uint8_t get_on_sequence() const { return on_seq_; }
    const uint8_t *get_on_token() const { return on_token_; }
    uint8_t get_off_sequence() const { return off_seq_; }
    const uint8_t *get_off_token() const { return off_token_; }
    uint8_t get_dim_plus_sequence() const { return dim_plus_seq_; }
    const uint8_t *get_dim_plus_token() const { return dim_plus_token_; }
    uint8_t get_dim_minus_sequence() const { return dim_minus_seq_; }
    const uint8_t *get_dim_minus_token() const { return dim_minus_token_; }
    bool has_dim_plus() const { return has_dim_plus_; }
    bool has_dim_minus() const { return has_dim_minus_; }
    uint16_t get_dst() const { return dst_; }

    const uint8_t *get_shared_secret() const { return shared_secret_; }
    size_t get_shared_secret_len() const { return shared_secret_len_; }
    const uint8_t *get_acl_payload() const { return acl_payload_; }
    size_t get_acl_len() const { return acl_len_; }
    const std::string &get_switch_eui() const { return switch_eui_; }
    const std::vector<LightInfo> &get_lights() const { return lights_; }

 protected:
    uint8_t on_seq_{0};
    uint8_t on_token_[LITEWAVE_TOKEN_LEN]{};
    uint8_t off_seq_{0};
    uint8_t off_token_[LITEWAVE_TOKEN_LEN]{};
    uint8_t dim_plus_seq_{0};
    uint8_t dim_plus_token_[LITEWAVE_TOKEN_LEN]{};
    uint8_t dim_minus_seq_{0};
    uint8_t dim_minus_token_[LITEWAVE_TOKEN_LEN]{};
    bool has_dim_plus_{false};
    bool has_dim_minus_{false};
    uint16_t dst_{0xFFF0};
    uint8_t shared_secret_[LITEWAVE_SHARED_SECRET_LEN]{};
    size_t shared_secret_len_{0};
    uint8_t acl_payload_[16]{};
    size_t acl_len_{0};
    std::string switch_eui_{};
    std::vector<LightInfo> lights_;
};

class LitewaveComponent : public Component {
 public:
    void setup() override;
    void loop() override;
    void dump_config() override;
    float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

    void set_channel(uint8_t ch) { channel_ = ch; }
    void set_pan_id(uint16_t pan) { pan_id_ = pan; }
    void set_admin_key(uint16_t key) { admin_key_ = key; }
    void set_sniff(bool sniff) { sniff_ = sniff; }
    void add_group(LitewaveGroup *group) { groups_.push_back(group); }

    void send_on(LitewaveGroup *group);
    void send_off(LitewaveGroup *group);
    void send_dim_plus(LitewaveGroup *group);
    void send_dim_minus(LitewaveGroup *group);

    void provision_light(const std::string &light_id);

    // Called from ISR context via C callback trampolines
    void on_tx_done(bool success);
    void on_rx_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info);

 protected:
    static void provision_task_trampoline(void *arg);
    void run_provision_task(const std::string &light_id);
    void transmit_command(uint8_t seq, const uint8_t *token);
    bool transmit_frame(const uint8_t *frame_data, uint8_t frame_len);
    void build_litewave_frame(uint8_t *buf, uint8_t *len, uint8_t seq, uint16_t dst, const uint8_t *token);
    void start_receive();
    void process_rx_frame(const RxFrame &frame);

    uint8_t channel_{0};
    uint16_t pan_id_{0};
    uint16_t admin_key_{0};
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
