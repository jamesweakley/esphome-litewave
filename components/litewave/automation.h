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

}  // namespace litewave
}  // namespace esphome
