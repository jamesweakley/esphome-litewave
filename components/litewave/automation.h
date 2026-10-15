#pragma once

#include "esphome/core/automation.h"
#include "litewave.h"

namespace esphome {
namespace litewave {

template<typename... Ts>
class LitewaveSendOnAction : public Action<Ts...> {
 public:
    LitewaveSendOnAction(LitewaveComponent *parent) : parent_(parent) {}
    void set_group(LitewaveGroup *group) { group_ = group; }
    void play(const Ts &...x) override { parent_->send_on(group_); }

 protected:
    LitewaveComponent *parent_;
    LitewaveGroup *group_{nullptr};
};

template<typename... Ts>
class LitewaveSendOffAction : public Action<Ts...> {
 public:
    LitewaveSendOffAction(LitewaveComponent *parent) : parent_(parent) {}
    void set_group(LitewaveGroup *group) { group_ = group; }
    void play(const Ts &...x) override { parent_->send_off(group_); }

 protected:
    LitewaveComponent *parent_;
    LitewaveGroup *group_{nullptr};
};

template<typename... Ts>
class LitewaveSendDimPlusAction : public Action<Ts...> {
 public:
    LitewaveSendDimPlusAction(LitewaveComponent *parent) : parent_(parent) {}
    void set_group(LitewaveGroup *group) { group_ = group; }
    void play(const Ts &...x) override { parent_->send_dim_plus(group_); }

 protected:
    LitewaveComponent *parent_;
    LitewaveGroup *group_{nullptr};
};

template<typename... Ts>
class LitewaveSendDimMinusAction : public Action<Ts...> {
 public:
    LitewaveSendDimMinusAction(LitewaveComponent *parent) : parent_(parent) {}
    void set_group(LitewaveGroup *group) { group_ = group; }
    void play(const Ts &...x) override { parent_->send_dim_minus(group_); }

 protected:
    LitewaveComponent *parent_;
    LitewaveGroup *group_{nullptr};
};

template<typename... Ts>
class LitewaveProvisionLightAction : public Action<Ts...> {
 public:
    LitewaveProvisionLightAction(LitewaveComponent *parent) : parent_(parent) {}
    TEMPLATABLE_VALUE(std::string, light_id)
    TEMPLATABLE_VALUE(std::string, pairing_code)

    void play(const Ts &...x) override {
        std::string id = this->light_id_.value(x...);
        std::string code = this->pairing_code_.value(x...);
        this->parent_->provision_light(id, code);
    }

 protected:
    LitewaveComponent *parent_;
};

}  // namespace litewave
}  // namespace esphome
