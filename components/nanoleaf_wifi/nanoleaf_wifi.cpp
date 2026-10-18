#include "nanoleaf_wifi.h"

namespace esphome {
namespace nanoleaf_wifi {

static const char *const TAG = "nanoleaf_wifi";

void NanoleafWifiComponent::init_resolver_task(void *pvParameters) {
    auto *self = static_cast<NanoleafWifiComponent *>(pvParameters);
    // Wait a brief moment for WiFi connection to stabilize
    vTaskDelay(pdMS_TO_TICKS(1000));
    for (auto &light : self->lights_) {
        self->resolve_host(light);
    }
    vTaskDelete(nullptr);
}

void NanoleafWifiComponent::setup() {
    ESP_LOGCONFIG(TAG, "Nanoleaf WiFi component initialized.");
    xTaskCreate(init_resolver_task, "nl_resolver", 4096, this, tskIDLE_PRIORITY + 1, nullptr);
}

void NanoleafWifiComponent::dump_config() {
    ESP_LOGCONFIG(TAG, "Nanoleaf WiFi Component:");
    for (const auto &light : lights_) {
        ESP_LOGCONFIG(TAG, "  Light '%s':", light.id.c_str());
        ESP_LOGCONFIG(TAG, "    Host: %s:%d", light.host.c_str(), light.port);
        ESP_LOGCONFIG(TAG, "    UDP Port: %d", light.udp_port);
        ESP_LOGCONFIG(TAG, "    Auth Token: %s", light.auth_token.empty() ? "(none - needs provision)" : "[configured]");
    }
}

void NanoleafWifiComponent::add_light(const std::string &id, const std::string &host,
                                      uint16_t port, uint16_t udp_port, const std::string &auth_token) {
    NanoleafWifiLight l;
    l.id = id;
    l.host = host;
    l.port = port != 0 ? port : 12566;
    l.udp_port = udp_port != 0 ? udp_port : 60222;
    l.auth_token = auth_token;
    lights_.push_back(l);
}

NanoleafWifiLight *NanoleafWifiComponent::find_light(const std::string &light_id) {
    for (auto &light : lights_) {
        if (light.id == light_id) {
            return &light;
        }
    }
    return nullptr;
}

bool NanoleafWifiComponent::resolve_host(NanoleafWifiLight &light) {
    if (!light.resolved_ip.empty()) {
        return true;
    }

    // Fast check: if host is already an IPv4 literal, avoid DNS query
    struct in_addr dummy;
    if (inet_pton(AF_INET, light.host.c_str(), &dummy) == 1) {
        light.resolved_ip = light.host;
        return true;
    }

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int err = getaddrinfo(light.host.c_str(), nullptr, &hints, &res);
    if (err == 0 && res) {
        char ip_str[INET_ADDRSTRLEN];
        auto *ipv4 = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, sizeof(ip_str));
        light.resolved_ip = ip_str;
        freeaddrinfo(res);
        ESP_LOGI(TAG, "Resolved '%s' -> %s", light.host.c_str(), light.resolved_ip.c_str());
        return true;
    }

    ESP_LOGW(TAG, "Failed to resolve DNS hostname '%s' (err=%d)", light.host.c_str(), err);
    return false;
}

bool NanoleafWifiComponent::request_new_auth_token(NanoleafWifiLight &light) {
    if (light.resolved_ip.empty() && !resolve_host(light)) {
        return false;
    }

    int sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;

    struct timeval tv{ .tv_sec = 5, .tv_usec = 0 };
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(light.port);
    inet_pton(AF_INET, light.resolved_ip.c_str(), &addr.sin_addr);

    if (::connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "TCP connect to %s:%d failed: errno %d", light.resolved_ip.c_str(), light.port, errno);
        ::close(sock);
        return false;
    }

    std::string req = "POST /api/v1/new HTTP/1.1\r\nHost: " + light.host +
                      "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    ::send(sock, req.c_str(), req.length(), 0);

    char resp[1024];
    int n = ::recv(sock, resp, sizeof(resp) - 1, 0);
    ::close(sock);

    if (n <= 0) {
        ESP_LOGE(TAG, "No response from %s on /api/v1/new", light.resolved_ip.c_str());
        return false;
    }
    resp[n] = '\0';
    std::string s(resp);

    if (s.find("403 Forbidden") != std::string::npos) {
        ESP_LOGW(TAG, "Pairing rejected (403 Forbidden): Press 'Connect to API' in the Nanoleaf App device settings, then retry.");
        return false;
    }

    // Parse "auth_token":"..."
    auto pos = s.find("\"auth_token\"");
    if (pos != std::string::npos) {
        auto colon = s.find(':', pos);
        auto quote1 = s.find('\"', colon);
        auto quote2 = s.find('\"', quote1 + 1);
        if (quote1 != std::string::npos && quote2 != std::string::npos) {
            light.auth_token = s.substr(quote1 + 1, quote2 - quote1 - 1);
            ESP_LOGI(TAG, "Successfully acquired Auth Token for '%s': %s", light.id.c_str(), light.auth_token.c_str());
            ESP_LOGI(TAG, "You can save this in your YAML: auth_token: \"%s\"", light.auth_token.c_str());
            return true;
        }
    }

    ESP_LOGW(TAG, "Unexpected response on /api/v1/new:\n%s", resp);
    return false;
}

bool NanoleafWifiComponent::set_power_state(NanoleafWifiLight &light, bool on) {
    if (light.auth_token.empty()) return false;
    if (light.resolved_ip.empty() && !resolve_host(light)) return false;

    int sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;

    struct timeval tv{ .tv_sec = 5, .tv_usec = 0 };
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(light.port);
    inet_pton(AF_INET, light.resolved_ip.c_str(), &addr.sin_addr);

    if (::connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ::close(sock);
        return false;
    }

    std::string payload = on ? "{\"on\":{\"value\":true}}" : "{\"on\":{\"value\":false}}";
    std::string req = "PUT /api/v1/" + light.auth_token + "/state HTTP/1.1\r\n" +
                      "Host: " + light.host + "\r\n" +
                      "Content-Type: application/json\r\n" +
                      "Content-Length: " + std::to_string(payload.length()) + "\r\n" +
                      "Connection: close\r\n\r\n" +
                      payload;

    ::send(sock, req.c_str(), req.length(), 0);
    char resp[256];
    int n = ::recv(sock, resp, sizeof(resp) - 1, 0);
    ::close(sock);
    return (n > 0);
}

bool NanoleafWifiComponent::activate_extcontrol(NanoleafWifiLight &light) {
    if (light.auth_token.empty()) {
        ESP_LOGE(TAG, "Cannot activate extControl: no auth_token for light '%s'", light.id.c_str());
        return false;
    }
    if (light.resolved_ip.empty() && !resolve_host(light)) {
        return false;
    }

    // Ensure bulb power state is ON before activating extControl
    set_power_state(light, true);

    int sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;

    struct timeval tv{ .tv_sec = 5, .tv_usec = 0 };
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(light.port);
    inet_pton(AF_INET, light.resolved_ip.c_str(), &addr.sin_addr);

    if (::connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "TCP connect to %s:%d failed: errno %d", light.resolved_ip.c_str(), light.port, errno);
        ::close(sock);
        return false;
    }

    std::string payload = "{\"write\":{\"command\":\"display\",\"animType\":\"extControl\",\"extControlVersion\":\"v2\"}}";
    std::string req = "PUT /api/v1/" + light.auth_token + "/effects HTTP/1.1\r\n" +
                      "Host: " + light.host + "\r\n" +
                      "Content-Type: application/json\r\n" +
                      "Content-Length: " + std::to_string(payload.length()) + "\r\n" +
                      "Connection: close\r\n\r\n" +
                      payload;

    ::send(sock, req.c_str(), req.length(), 0);

    char resp[512];
    int n = ::recv(sock, resp, sizeof(resp) - 1, 0);
    ::close(sock);

    if (n > 0) {
        resp[n] = '\0';
        std::string s(resp);
        if (s.find("200 OK") != std::string::npos || s.find("204 No Content") != std::string::npos) {
            light.extcontrol_active = true;
            ESP_LOGI(TAG, "extControl mode successfully activated on light '%s' (%s)",
                     light.id.c_str(), light.resolved_ip.c_str());
            return true;
        }
        ESP_LOGW(TAG, "extControl activation returned error:\n%s", resp);
    }
    return false;
}

bool NanoleafWifiComponent::send_udp_frame(NanoleafWifiLight &light, uint8_t r, uint8_t g, uint8_t b, uint8_t w, uint16_t transition_100ms) {
    if (udp_sock_ < 0) {
        udp_sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_sock_ < 0) return false;
    }

    if (light.resolved_ip.empty() && !resolve_host(light)) {
        return false;
    }

    // Binary format for extControl v2 (1 panel):
    // [NumPanels (2B BE = 1)] [PanelId (2B BE = 0)] [R (1B)] [G (1B)] [B (1B)] [W (1B = 0)] [Transition (2B BE)]
    uint8_t frame[10];
    frame[0] = 0x00; frame[1] = 0x01; // 1 panel
    frame[2] = 0x00; frame[3] = 0x00; // panel ID 0
    frame[4] = r;
    frame[5] = g;
    frame[6] = b;
    frame[7] = w;
    frame[8] = (transition_100ms >> 8) & 0xFF;
    frame[9] = transition_100ms & 0xFF;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(light.udp_port);
    inet_pton(AF_INET, light.resolved_ip.c_str(), &addr.sin_addr);

    ssize_t sent = ::sendto(udp_sock_, frame, sizeof(frame), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (sent < 0) {
        ESP_LOGW(TAG, "sendto() UDP frame to %s:%d failed: errno %d", light.resolved_ip.c_str(), light.udp_port, errno);
        return false;
    }
    ESP_LOGD(TAG, "UDP stream frame sent to %s:%d (R=%d G=%d B=%d)", light.resolved_ip.c_str(), light.udp_port, r, g, b);
    return true;
}

void NanoleafWifiComponent::send_on(const std::string &light_id, uint8_t r, uint8_t g, uint8_t b, uint8_t w, uint32_t transition_ms) {
    auto *light = find_light(light_id);
    if (!light) {
        ESP_LOGE(TAG, "Light '%s' not found", light_id.c_str());
        return;
    }
    uint16_t t_100ms = (transition_ms + 50) / 100;
    send_udp_frame(*light, r, g, b, w, t_100ms);
}

void NanoleafWifiComponent::send_off(const std::string &light_id, uint32_t transition_ms) {
    auto *light = find_light(light_id);
    if (!light) {
        ESP_LOGE(TAG, "Light '%s' not found", light_id.c_str());
        return;
    }
    uint16_t t_100ms = (transition_ms + 50) / 100;
    send_udp_frame(*light, 0, 0, 0, 0, t_100ms);
}

void NanoleafWifiComponent::set_color(const std::string &light_id, uint8_t r, uint8_t g, uint8_t b, uint8_t w, uint32_t transition_ms) {
    auto *light = find_light(light_id);
    if (!light) {
        ESP_LOGE(TAG, "Light '%s' not found", light_id.c_str());
        return;
    }
    uint16_t t_100ms = (transition_ms + 50) / 100;
    send_udp_frame(*light, r, g, b, w, t_100ms);
}

void NanoleafWifiComponent::provision_task(void *pvParameters) {
    auto *ctx = static_cast<ProvisionContext *>(pvParameters);
    auto *light = ctx->parent->find_light(ctx->light_id);

    if (!light) {
        ESP_LOGE(TAG, "Light '%s' not found for provisioning", ctx->light_id.c_str());
        delete ctx;
        vTaskDelete(nullptr);
        return;
    }

    if (!ctx->auth_token.empty()) {
        light->auth_token = ctx->auth_token;
    }

    ESP_LOGI(TAG, "Starting provisioning for light '%s' (%s)...", light->id.c_str(), light->host.c_str());

    if (!ctx->parent->resolve_host(*light)) {
        ESP_LOGE(TAG, "Could not resolve hostname '%s'", light->host.c_str());
        delete ctx;
        vTaskDelete(nullptr);
        return;
    }

    if (light->auth_token.empty()) {
        ESP_LOGI(TAG, "Requesting new auth token on %s:%d...", light->resolved_ip.c_str(), light->port);
        if (!ctx->parent->request_new_auth_token(*light)) {
            ESP_LOGE(TAG, "Failed to get auth token. Make sure you press 'Connect to API' in the Nanoleaf App.");
            delete ctx;
            vTaskDelete(nullptr);
            return;
        }
    }

    ESP_LOGI(TAG, "Activating extControl UDP streaming mode on %s:%d...", light->resolved_ip.c_str(), light->port);
    if (ctx->parent->activate_extcontrol(*light)) {
        ESP_LOGI(TAG, "Provisioning succeeded! Light '%s' is now ready for UDP extControl.", light->id.c_str());
    } else {
        ESP_LOGE(TAG, "Failed to activate extControl mode on light '%s'", light->id.c_str());
    }

    delete ctx;
    vTaskDelete(nullptr);
}

void NanoleafWifiComponent::provision_light(const std::string &light_id, const std::string &override_auth_token) {
    ESP_LOGI(TAG, "Triggering background provision for light '%s'...", light_id.c_str());
    auto *ctx = new ProvisionContext{this, light_id, override_auth_token};
    BaseType_t res = xTaskCreate(provision_task, "nl_wifi_prov", 4096, ctx, tskIDLE_PRIORITY + 1, nullptr);
    if (res != pdPASS) {
        ESP_LOGE(TAG, "Failed to create background provisioning task (error %d)", res);
        delete ctx;
    }
}

void NanoleafWifiComponent::extcontrol_task(void *pvParameters) {
    auto *ctx = static_cast<ProvisionContext *>(pvParameters);
    auto *light = ctx->parent->find_light(ctx->light_id);

    if (!light) {
        ESP_LOGE(TAG, "Light '%s' not found for enable_extcontrol", ctx->light_id.c_str());
        delete ctx;
        vTaskDelete(nullptr);
        return;
    }

    if (!ctx->auth_token.empty()) {
        light->auth_token = ctx->auth_token;
    }

    if (light->auth_token.empty()) {
        ESP_LOGE(TAG, "Cannot enable extControl on '%s': no auth_token configured", light->id.c_str());
        delete ctx;
        vTaskDelete(nullptr);
        return;
    }

    ESP_LOGI(TAG, "Enabling extControl mode for light '%s' (%s)...", light->id.c_str(), light->host.c_str());

    if (!ctx->parent->resolve_host(*light)) {
        ESP_LOGE(TAG, "Could not resolve hostname '%s'", light->host.c_str());
        delete ctx;
        vTaskDelete(nullptr);
        return;
    }

    if (ctx->parent->activate_extcontrol(*light)) {
        ESP_LOGI(TAG, "extControl mode successfully enabled for light '%s'.", light->id.c_str());
    } else {
        ESP_LOGE(TAG, "Failed to activate extControl mode on light '%s'", light->id.c_str());
    }

    delete ctx;
    vTaskDelete(nullptr);
}

void NanoleafWifiComponent::enable_extcontrol(const std::string &light_id, const std::string &override_auth_token) {
    ESP_LOGI(TAG, "Triggering background enable_extcontrol for light '%s'...", light_id.c_str());
    auto *ctx = new ProvisionContext{this, light_id, override_auth_token};
    BaseType_t res = xTaskCreate(extcontrol_task, "nl_extctrl", 4096, ctx, tskIDLE_PRIORITY + 1, nullptr);
    if (res != pdPASS) {
        ESP_LOGE(TAG, "Failed to create extcontrol background task (error %d)", res);
        delete ctx;
    }
}

}  // namespace nanoleaf_wifi
}  // namespace esphome
