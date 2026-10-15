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
    void play(Ts... x) override { parent_->send_on(group_); }

 protected:
    LitewaveComponent *parent_;
    LitewaveGroup *group_{nullptr};
};

template<typename... Ts>
class LitewaveSendOffAction : public Action<Ts...> {
 public:
    LitewaveSendOffAction(LitewaveComponent *parent) : parent_(parent) {}
    void set_group(LitewaveGroup *group) { group_ = group; }
    void play(Ts... x) override { parent_->send_off(group_); }

 protected:
    LitewaveComponent *parent_;
    LitewaveGroup *group_{nullptr};
};

template<typename... Ts>
class LitewaveSendDimPlusAction : public Action<Ts...> {
 public:
    LitewaveSendDimPlusAction(LitewaveComponent *parent) : parent_(parent) {}
    void set_group(LitewaveGroup *group) { group_ = group; }
    void play(Ts... x) override { parent_->send_dim_plus(group_); }

 protected:
    LitewaveComponent *parent_;
    LitewaveGroup *group_{nullptr};
};

template<typename... Ts>
class LitewaveSendDimMinusAction : public Action<Ts...> {
 public:
    LitewaveSendDimMinusAction(LitewaveComponent *parent) : parent_(parent) {}
    void set_group(LitewaveGroup *group) { group_ = group; }
    void play(Ts... x) override { parent_->send_dim_minus(group_); }

 protected:
    LitewaveComponent *parent_;
    LitewaveGroup *group_{nullptr};
};

template<typename... Ts>
class LitewaveProvisionLightAction : public Action<Ts...> {
 public:
    LitewaveProvisionLightAction(LitewaveComponent *parent) : parent_(parent) {}
    void set_light_id(const std::string &id) { light_id_ = id; }
    void play(Ts... x) override { parent_->provision_light(light_id_); }

 protected:
    LitewaveComponent *parent_;
    std::string light_id_{};
};

}  // namespace litewave
}  // namespace esphome
