#include "litewave.h"
#include "ltpdu_v3.h"
#include "mdns.h"
#include "esp_netif.h"

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
        ESP_LOGCONFIG(TAG, "    ON seq=0x%02X token=%s", group->get_on_sequence(), token_hex);
        for (int i = 0; i < LITEWAVE_TOKEN_LEN; i++) {
            sprintf(&token_hex[i * 2], "%02X", group->get_off_token()[i]);
        }
        ESP_LOGCONFIG(TAG, "    OFF seq=0x%02X token=%s", group->get_off_sequence(), token_hex);
        if (group->has_dim_plus()) {
            for (int i = 0; i < LITEWAVE_TOKEN_LEN; i++) {
                sprintf(&token_hex[i * 2], "%02X", group->get_dim_plus_token()[i]);
            }
            ESP_LOGCONFIG(TAG, "    DIM+ seq=0x%02X token=%s", group->get_dim_plus_sequence(), token_hex);
        }
        if (group->has_dim_minus()) {
            for (int i = 0; i < LITEWAVE_TOKEN_LEN; i++) {
                sprintf(&token_hex[i * 2], "%02X", group->get_dim_minus_token()[i]);
            }
            ESP_LOGCONFIG(TAG, "    DIM- seq=0x%02X token=%s", group->get_dim_minus_sequence(), token_hex);
        }
        if (group->get_shared_secret_len() > 0) {
            ESP_LOGCONFIG(TAG, "    Shared secret: %d bytes", group->get_shared_secret_len());
        }
        if (!group->get_switch_eui().empty()) {
            ESP_LOGCONFIG(TAG, "    Switch EUI: %s", group->get_switch_eui().c_str());
        }
        if (group->get_acl_len() > 0) {
            ESP_LOGCONFIG(TAG, "    ACL payload: %d bytes", group->get_acl_len());
        }
        ESP_LOGCONFIG(TAG, "    Lights: %d", group->get_lights().size());
        for (const auto &light : group->get_lights()) {
            std::string desc = light.name.empty() ? (light.id.empty() ? "Light" : light.id) : light.name;
            if (!light.id.empty() && !light.host.empty()) {
                ESP_LOGCONFIG(TAG, "      [%s] %s @ %s", light.id.c_str(), desc.c_str(), light.host.c_str());
            } else if (!light.id.empty()) {
                ESP_LOGCONFIG(TAG, "      [%s] %s", light.id.c_str(), desc.c_str());
            } else {
                ESP_LOGCONFIG(TAG, "      %s @ %s", desc.c_str(), light.host.c_str());
            }
        }
    }
}

void LitewaveComponent::send_on(LitewaveGroup *group) {
    ESP_LOGI(TAG, "Sending ON (seq=0x%02X)", group->get_on_sequence());
    transmit_command(group->get_on_sequence(), group->get_on_token());
}

void LitewaveComponent::send_off(LitewaveGroup *group) {
    ESP_LOGI(TAG, "Sending OFF (seq=0x%02X)", group->get_off_sequence());
    transmit_command(group->get_off_sequence(), group->get_off_token());
}

void LitewaveComponent::send_dim_plus(LitewaveGroup *group) {
    if (!group->has_dim_plus()) {
        ESP_LOGW(TAG, "DIM+ not configured for this group");
        return;
    }
    ESP_LOGI(TAG, "Sending DIM+ (seq=0x%02X)", group->get_dim_plus_sequence());
    transmit_command(group->get_dim_plus_sequence(), group->get_dim_plus_token());
}

void LitewaveComponent::send_dim_minus(LitewaveGroup *group) {
    if (!group->has_dim_minus()) {
        ESP_LOGW(TAG, "DIM- not configured for this group");
        return;
    }
    ESP_LOGI(TAG, "Sending DIM- (seq=0x%02X)", group->get_dim_minus_sequence());
    transmit_command(group->get_dim_minus_sequence(), group->get_dim_minus_token());
}

struct ProvisionContext {
    LitewaveComponent *component;
    std::string light_id;
    std::string pairing_code;
};

void LitewaveComponent::provision_task_trampoline(void *arg) {
    auto *ctx = static_cast<ProvisionContext *>(arg);
    if (ctx && ctx->component) {
        ctx->component->run_provision_task(ctx->light_id, ctx->pairing_code);
    }
    delete ctx;
    vTaskDelete(nullptr);
}

void LitewaveComponent::provision_light(const std::string &light_id, const std::string &override_pairing_code) {
    ESP_LOGI(TAG, "Starting background provisioning task for light '%s'", light_id.c_str());
    auto *ctx = new ProvisionContext{this, light_id, override_pairing_code};
    BaseType_t res = xTaskCreate(
        provision_task_trampoline,
        "ltpdu_prov",
        8192,
        ctx,
        tskIDLE_PRIORITY + 1,
        nullptr
    );
    if (res != pdPASS) {
        ESP_LOGE(TAG, "Failed to create background provisioning task (error %d)", res);
        delete ctx;
    }
}

struct DiscoveredLight {
    std::string ip;
    uint16_t port{12566};
    std::string instance_name;
};

static bool query_and_match_mdns(const char *service_type, const char *proto,
                                  uint32_t total_timeout_ms, const std::string &target_id,
                                  DiscoveredLight &out) {
    std::string target_upper = target_id;
    for (auto &c : target_upper) c = toupper((unsigned char)c);

    int64_t start_time = esp_timer_get_time() / 1000;
    std::vector<std::string> seen_instances;

    while ((esp_timer_get_time() / 1000) - start_time < total_timeout_ms) {
        int64_t elapsed = (esp_timer_get_time() / 1000) - start_time;
        uint32_t remaining = total_timeout_ms > elapsed ? (total_timeout_ms - elapsed) : 0;
        if (remaining == 0) break;
        uint32_t slice_timeout = remaining > 3000 ? 3000 : remaining;

        mdns_result_t *results = nullptr;
        esp_err_t err = mdns_query_ptr(service_type, proto, slice_timeout, 255, &results);
        if (err == ESP_OK && results) {
            mdns_result_t *r = results;
            while (r) {
                std::string inst = r->instance_name ? r->instance_name : "";
                std::string inst_upper = inst;
                for (auto &c : inst_upper) c = toupper((unsigned char)c);

                bool already_seen = false;
                for (const auto &s : seen_instances) {
                    if (s == inst) { already_seen = true; break; }
                }
                if (!already_seen && !inst.empty()) {
                    seen_instances.push_back(inst);
                    ESP_LOGI(TAG, "  Found mDNS device: '%s'", inst.c_str());
                }

                // Check if instance name ends with target_id, contains " <target_id>", or contains target_id
                bool match = false;
                if (inst_upper == target_upper ||
                    inst_upper.find(" " + target_upper) != std::string::npos ||
                    inst_upper.find("-" + target_upper) != std::string::npos ||
                    (inst_upper.length() >= target_upper.length() &&
                     inst_upper.rfind(target_upper) == inst_upper.length() - target_upper.length()) ||
                    inst_upper.find(target_upper) != std::string::npos) {
                    match = true;
                }

                // Also check TXT properties
                for (size_t t = 0; t < r->txt_count && !match; t++) {
                    std::string key = r->txt[t].key ? r->txt[t].key : "";
                    std::string val = r->txt[t].value ? r->txt[t].value : "";
                    std::string val_upper = val;
                    for (auto &c : val_upper) c = toupper((unsigned char)c);

                    if ((key == "id" || key == "eui64" || key == "eui") &&
                        (val_upper == target_upper ||
                         (val_upper.length() >= target_upper.length() &&
                          val_upper.rfind(target_upper) == val_upper.length() - target_upper.length()) ||
                         val_upper.find(target_upper) != std::string::npos)) {
                        match = true;
                        break;
                    }
                }

                if (match) {
                    mdns_ip_addr_t *a = r->addr;
                    int ip_count = 0;
                    while (a) {
                        char ip_buf[INET6_ADDRSTRLEN];
                        if (a->addr.type == ESP_IPADDR_TYPE_V6) {
                            inet_ntop(AF_INET6, &(a->addr.u_addr.ip6), ip_buf, sizeof(ip_buf));
                            ESP_LOGI(TAG, "  -> Address[%d]: %s (IPv6)", ip_count++, ip_buf);
                            if (out.ip.empty()) out.ip = ip_buf;
                        } else if (a->addr.type == ESP_IPADDR_TYPE_V4) {
                            inet_ntop(AF_INET, &(a->addr.u_addr.ip4), ip_buf, sizeof(ip_buf));
                            ESP_LOGI(TAG, "  -> Address[%d]: %s (IPv4)", ip_count++, ip_buf);
                            if (out.ip.empty()) out.ip = ip_buf;
                        }
                        a = a->next;
                    }
                    if (!out.ip.empty()) {
                        out.port = r->port != 0 ? r->port : 12566;
                        out.instance_name = inst;
                        ESP_LOGI(TAG, "  -> Matched target '%s': Using IP=%s:%d", target_id.c_str(), out.ip.c_str(), out.port);
                        for (size_t t = 0; t < r->txt_count; t++) {
                            std::string key = r->txt[t].key ? r->txt[t].key : "";
                            std::string val = r->txt[t].value ? r->txt[t].value : "";
                            ESP_LOGI(TAG, "     TXT %s=%s", key.c_str(), val.c_str());
                        }
                        mdns_query_results_free(results);
                        return true;
                    }
                }
                r = r->next;
            }
            mdns_query_results_free(results);
        }
    }

    ESP_LOGI(TAG, "mDNS %s.%s query finished (%d unique devices found, matched=%s)",
             service_type, proto, (int)seen_instances.size(), "NO");
    return false;
}

static bool resolve_light_mdns(const std::string &target_id, DiscoveredLight &out) {
    // Ensure IPv6 link-local is created on default WiFi station interface for Thread mDNS multicast
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif) {
        esp_netif_create_ip6_linklocal(netif);
        esp_ip6_addr_t ip6_addrs[4];
        int num_addrs = esp_netif_get_all_ip6(netif, ip6_addrs);
        ESP_LOGI(TAG, "ESP32 has %d IPv6 address(es) on Wi-Fi interface:", num_addrs);
        for (int i = 0; i < num_addrs; i++) {
            char ip6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6_addrs[i], ip6_str, sizeof(ip6_str));
            ESP_LOGI(TAG, "  [%d] %s", i, ip6_str);
        }
    }

    esp_err_t err = mdns_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "mdns_init: %d", err);
    }

    // 1. Try _ltpdu._udp (20-second timeout for Thread mesh mDNS propagation)
    ESP_LOGI(TAG, "Querying _ltpdu._udp (20s timeout)...");
    if (query_and_match_mdns("_ltpdu", "_udp", 20000, target_id, out)) {
        return true;
    }

    // 2. Fallback: try _nanoleafms._udp
    ESP_LOGI(TAG, "Checking fallback service _nanoleafms._udp (5s timeout)...");
    if (query_and_match_mdns("_nanoleafms", "_udp", 5000, target_id, out)) {
        return true;
    }

    // 3. Fallback: try _nanoleafapi._tcp
    ESP_LOGI(TAG, "Checking fallback service _nanoleafapi._tcp (5s timeout)...");
    if (query_and_match_mdns("_nanoleafapi", "_tcp", 5000, target_id, out)) {
        return true;
    }

    return false;
}

void LitewaveComponent::run_provision_task(const std::string &light_id, const std::string &override_pairing_code) {
    LitewaveGroup *target_group = nullptr;
    const LightInfo *target_light = nullptr;

    for (auto *group : groups_) {
        for (const auto &light : group->get_lights()) {
            if (light.id == light_id || light.name == light_id) {
                target_group = group;
                target_light = &light;
                break;
            }
        }
        if (target_light) break;
    }

    if (!target_light || !target_group) {
        ESP_LOGE(TAG, "Light '%s' not found in any configured group", light_id.c_str());
        return;
    }

    if (target_group->get_shared_secret_len() == 0) {
        ESP_LOGE(TAG, "No shared_secret configured for the group containing light '%s'", light_id.c_str());
        return;
    }

    std::string pairing_code = !override_pairing_code.empty() ? override_pairing_code : target_light->pairing_code;
    if (pairing_code.empty()) {
        ESP_LOGE(TAG, "No pairing code available for light '%s' (not in YAML and none provided in service call)", light_id.c_str());
        return;
    }
    if (!override_pairing_code.empty()) {
        ESP_LOGI(TAG, "Using dynamic pairing code provided from service call");
    } else {
        ESP_LOGI(TAG, "Using static pairing code from YAML configuration");
    }

    std::string light_name = target_light->name.empty() ? (target_light->id.empty() ? "Light" : target_light->id) : target_light->name;
    std::string srp_service_name = !target_light->id.empty() ? ("Nanoleaf DL " + target_light->id) : light_name;
    std::string target_host = target_light->host;
    uint16_t target_port = 12566;

    if (target_host.empty()) {
        ESP_LOGI(TAG, "Resolving light '%s' via mDNS (_ltpdu._udp)...", light_id.c_str());
        DiscoveredLight disc;
        std::string lookup_id = !target_light->id.empty() ? target_light->id : light_id;
        if (resolve_light_mdns(lookup_id, disc)) {
            target_host = disc.ip;
            target_port = disc.port;
            if (!disc.instance_name.empty()) {
                srp_service_name = disc.instance_name;
            }
            ESP_LOGI(TAG, "mDNS resolved light '%s' to %s:%d (service '%s')",
                     lookup_id.c_str(), target_host.c_str(), target_port, srp_service_name.c_str());
        } else {
            ESP_LOGE(TAG, "Could not resolve light '%s' via mDNS and no 'host' specified in YAML", light_id.c_str());
            return;
        }
    }

    ESP_LOGI(TAG, "Provisioning light '%s' (%s) at %s:%d", light_name.c_str(), srp_service_name.c_str(), target_host.c_str(), target_port);

    bool ok = provision_light_sync(
        target_host,
        target_port,
        pairing_code,
        srp_service_name,
        target_group->get_shared_secret(),
        target_group->get_shared_secret_len(),
        pan_id_,
        channel_,
        admin_key_,
        target_group->get_acl_payload(),
        target_group->get_acl_len()
    );
    if (ok) {
        ESP_LOGI(TAG, "Provisioning succeeded for '%s'", light_name.c_str());
    } else {
        ESP_LOGE(TAG, "Provisioning FAILED for '%s'", light_name.c_str());
    }
}

void LitewaveComponent::build_litewave_frame(uint8_t *buf, uint8_t *len,
                                               uint8_t seq, uint16_t dst,
                                               const uint8_t *token) {
    uint8_t i = 0;
    buf[i++] = LITEWAVE_FCF_LO;
    buf[i++] = LITEWAVE_FCF_HI;
    buf[i++] = seq;
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

void LitewaveComponent::transmit_command(uint8_t seq, const uint8_t *token) {
    if (!ready_) {
        ESP_LOGW(TAG, "Ignoring transmit before setup complete");
        return;
    }
    uint8_t frame[32];
    uint8_t frame_len;
    build_litewave_frame(frame, &frame_len, seq, LITEWAVE_DST_MULTICAST, token);

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

    ESP_LOGI(TAG, " ");
    ESP_LOGI(TAG, "=== Litewave command captured (rssi=%d) ===", frame.rssi);
    ESP_LOGI(TAG, "  sequence: 0x%02X", seq);
    ESP_LOGI(TAG, "  token: \"%s\"", token_hex);
    ESP_LOGI(TAG, " ");
    ESP_LOGI(TAG, "Add to your YAML group config:");
    ESP_LOGI(TAG, "  on_sequence: 0x%02X     # if this was an ON press", seq);
    ESP_LOGI(TAG, "  on_token: \"%s\"   # if this was an ON press", token_hex);
    ESP_LOGI(TAG, "  off_sequence: 0x%02X    # if this was an OFF press", seq);
    ESP_LOGI(TAG, "  off_token: \"%s\"  # if this was an OFF press", token_hex);
    ESP_LOGI(TAG, "===");
}

}  // namespace litewave
}  // namespace esphome
