#pragma once

#include <vector>
#include <string>
#include <cstring>
#include "esphome/core/component.h"
#include "esphome/core/log.h"
#include "esphome/core/automation.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

namespace esphome {
namespace nanoleaf_wifi {

struct NanoleafWifiLight {
    std::string id;
    std::string host;
    uint16_t port{12566};
    uint16_t udp_port{60222};
    std::string auth_token;
    bool extcontrol_active{false};
    std::string resolved_ip;
};

class NanoleafWifiComponent : public Component {
 public:
    float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }
    void setup() override;
    void dump_config() override;

    void add_light(const std::string &id, const std::string &host, uint16_t port, uint16_t udp_port, const std::string &auth_token);

    void provision_light(const std::string &light_id, const std::string &override_auth_token = "");
    void enable_extcontrol(const std::string &light_id, const std::string &override_auth_token = "");
    void send_on(const std::string &light_id, uint8_t r = 255, uint8_t g = 255, uint8_t b = 255, uint8_t w = 0, uint32_t transition_ms = 100);
    void send_off(const std::string &light_id, uint32_t transition_ms = 100);
    void set_color(const std::string &light_id, uint8_t r, uint8_t g, uint8_t b, uint8_t w = 0, uint32_t transition_ms = 100);

 protected:
    NanoleafWifiLight *find_light(const std::string &light_id);
    bool resolve_host(NanoleafWifiLight &light);
    bool set_power_state(NanoleafWifiLight &light, bool on);
    bool activate_extcontrol(NanoleafWifiLight &light);
    bool request_new_auth_token(NanoleafWifiLight &light);
    bool send_udp_frame(NanoleafWifiLight &light, uint8_t r, uint8_t g, uint8_t b, uint8_t w, uint16_t transition_100ms);

    static void provision_task(void *pvParameters);
    static void extcontrol_task(void *pvParameters);

    struct ProvisionContext {
        NanoleafWifiComponent *parent;
        std::string light_id;
        std::string auth_token;
    };

    std::vector<NanoleafWifiLight> lights_;
    int udp_sock_{-1};
};

}  // namespace nanoleaf_wifi
}  // namespace esphome
