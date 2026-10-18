#pragma once

#include "esphome/core/automation.h"
#include "nanoleaf_wifi.h"

namespace esphome {
namespace nanoleaf_wifi {

template<typename... Ts>
class NanoleafProvisionAction : public Action<Ts...> {
 public:
    NanoleafProvisionAction(NanoleafWifiComponent *parent) : parent_(parent) {}
    TEMPLATABLE_VALUE(std::string, light_id)
    TEMPLATABLE_VALUE(std::string, auth_token)

    void play(const Ts &...x) override {
        std::string id = this->light_id_.value(x...);
        std::string token = this->auth_token_.value(x...);
        this->parent_->provision_light(id, token);
    }

 protected:
    NanoleafWifiComponent *parent_;
};

template<typename... Ts>
class NanoleafEnableExtControlAction : public Action<Ts...> {
 public:
    NanoleafEnableExtControlAction(NanoleafWifiComponent *parent) : parent_(parent) {}
    TEMPLATABLE_VALUE(std::string, light_id)
    TEMPLATABLE_VALUE(std::string, auth_token)

    void play(const Ts &...x) override {
        std::string id = this->light_id_.value(x...);
        std::string token = this->auth_token_.value(x...);
        this->parent_->enable_extcontrol(id, token);
    }

 protected:
    NanoleafWifiComponent *parent_;
};

template<typename... Ts>
class NanoleafSendOnAction : public Action<Ts...> {
 public:
    NanoleafSendOnAction(NanoleafWifiComponent *parent) : parent_(parent) {}
    TEMPLATABLE_VALUE(std::string, light_id)
    TEMPLATABLE_VALUE(uint8_t, red)
    TEMPLATABLE_VALUE(uint8_t, green)
    TEMPLATABLE_VALUE(uint8_t, blue)
    TEMPLATABLE_VALUE(uint8_t, white)
    TEMPLATABLE_VALUE(uint32_t, transition_ms)

    void play(const Ts &...x) override {
        std::string id = this->light_id_.value(x...);
        uint8_t r = this->red_.value(x...);
        uint8_t g = this->green_.value(x...);
        uint8_t b = this->blue_.value(x...);
        uint8_t w = this->white_.value(x...);
        uint32_t t = this->transition_ms_.value(x...);
        this->parent_->send_on(id, r, g, b, w, t);
    }

 protected:
    NanoleafWifiComponent *parent_;
};

template<typename... Ts>
class NanoleafSendOffAction : public Action<Ts...> {
 public:
    NanoleafSendOffAction(NanoleafWifiComponent *parent) : parent_(parent) {}
    TEMPLATABLE_VALUE(std::string, light_id)
    TEMPLATABLE_VALUE(uint32_t, transition_ms)

    void play(const Ts &...x) override {
        std::string id = this->light_id_.value(x...);
        uint32_t t = this->transition_ms_.value(x...);
        this->parent_->send_off(id, t);
    }

 protected:
    NanoleafWifiComponent *parent_;
};

template<typename... Ts>
class NanoleafSetColorAction : public Action<Ts...> {
 public:
    NanoleafSetColorAction(NanoleafWifiComponent *parent) : parent_(parent) {}
    TEMPLATABLE_VALUE(std::string, light_id)
    TEMPLATABLE_VALUE(uint8_t, red)
    TEMPLATABLE_VALUE(uint8_t, green)
    TEMPLATABLE_VALUE(uint8_t, blue)
    TEMPLATABLE_VALUE(uint8_t, white)
    TEMPLATABLE_VALUE(uint32_t, transition_ms)

    void play(const Ts &...x) override {
        std::string id = this->light_id_.value(x...);
        uint8_t r = this->red_.value(x...);
        uint8_t g = this->green_.value(x...);
        uint8_t b = this->blue_.value(x...);
        uint8_t w = this->white_.value(x...);
        uint32_t t = this->transition_ms_.value(x...);
        this->parent_->set_color(id, r, g, b, w, t);
    }

 protected:
    NanoleafWifiComponent *parent_;
};

template<typename... Ts>
class NanoleafSetBrightnessAction : public Action<Ts...> {
 public:
    NanoleafSetBrightnessAction(NanoleafWifiComponent *parent) : parent_(parent) {}
    TEMPLATABLE_VALUE(std::string, light_id)
    TEMPLATABLE_VALUE(uint8_t, brightness)
    TEMPLATABLE_VALUE(uint32_t, transition_ms)

    void play(const Ts &...x) override {
        std::string id = this->light_id_.value(x...);
        uint8_t b = this->brightness_.value(x...);
        uint32_t t = this->transition_ms_.value(x...);
        this->parent_->set_brightness(id, b, t);
    }

 protected:
    NanoleafWifiComponent *parent_;
};

template<typename... Ts>
class NanoleafSetColorTemperatureAction : public Action<Ts...> {
 public:
    NanoleafSetColorTemperatureAction(NanoleafWifiComponent *parent) : parent_(parent) {}
    TEMPLATABLE_VALUE(std::string, light_id)
    TEMPLATABLE_VALUE(uint16_t, color_temperature)
    TEMPLATABLE_VALUE(uint32_t, transition_ms)

    void play(const Ts &...x) override {
        std::string id = this->light_id_.value(x...);
        uint16_t ct = this->color_temperature_.value(x...);
        uint32_t t = this->transition_ms_.value(x...);
        this->parent_->set_color_temperature(id, ct, t);
    }

 protected:
    NanoleafWifiComponent *parent_;
};

}  // namespace nanoleaf_wifi
}  // namespace esphome
