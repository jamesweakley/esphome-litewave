#include "nanoleaf_wifi.h"
#include "esphome/components/network/util.h"
#include "mdns.h"
#include <algorithm>
#include <cmath>

namespace esphome {
namespace nanoleaf_wifi {

static const char *const TAG = "nanoleaf_wifi";

static void rgb_to_hs(uint8_t r, uint8_t g, uint8_t b, uint16_t &hue, uint8_t &sat) {
    float rf = r / 255.0f;
    float gf = g / 255.0f;
    float bf = b / 255.0f;
    float max_val = std::max(rf, std::max(gf, bf));
    float min_val = std::min(rf, std::min(gf, bf));
    float delta = max_val - min_val;

    float h = 0.0f;
    float s = (max_val == 0.0f) ? 0.0f : (delta / max_val);

    if (delta > 0.0001f) {
        if (max_val == rf) {
            h = 60.0f * (fmodf(((gf - bf) / delta), 6.0f));
        } else if (max_val == gf) {
            h = 60.0f * (((bf - rf) / delta) + 2.0f);
        } else {
            h = 60.0f * (((rf - gf) / delta) + 4.0f);
        }
        if (h < 0.0f) h += 360.0f;
    }

    hue = static_cast<uint16_t>(h + 0.5f);
    sat = static_cast<uint8_t>((s * 100.0f) + 0.5f);
}

static std::string normalize_id(const std::string &s) {
    std::string out;
    for (char c : s) {
        if (c != '_' && c != '-' && c != ' ') {
            out.push_back(tolower((unsigned char)c));
        }
    }
    return out;
}

void NanoleafWifiComponent::setup() {
    ESP_LOGCONFIG(TAG, "Nanoleaf WiFi HTTP component initialized.");
    cmd_queue_ = xQueueCreate(20, sizeof(HttpCommand));
    if (cmd_queue_ != nullptr) {
        xTaskCreate(worker_task, "nl_http_worker", 4096, this, tskIDLE_PRIORITY + 1, nullptr);
    } else {
        ESP_LOGE(TAG, "Failed to create HTTP command queue");
    }
}

void NanoleafWifiComponent::dump_config() {
    ESP_LOGCONFIG(TAG, "Nanoleaf WiFi Component (HTTP REST API):");
    for (const auto &light : lights_) {
        ESP_LOGCONFIG(TAG, "  Light '%s':", light.id.c_str());
        ESP_LOGCONFIG(TAG, "    Host: %s:%d", light.host.c_str(), light.port);
        ESP_LOGCONFIG(TAG, "    Auth Token: %s", light.auth_token.empty() ? "(none - needs provision)" : "[configured]");
    }
}

void NanoleafWifiComponent::add_light(const std::string &id, const std::string &host,
                                      uint16_t port, const std::string &auth_token) {
    NanoleafWifiLight l;
    l.id = id;
    l.host = host;
    l.port = port != 0 ? port : 12566;
    l.auth_token = auth_token;
    lights_.push_back(l);
}

NanoleafWifiLight *NanoleafWifiComponent::find_light(const std::string &light_id) {
    std::string norm_target = normalize_id(light_id);
    for (auto &light : lights_) {
        if (light.id == light_id || normalize_id(light.id) == norm_target) {
            return &light;
        }
    }
    ESP_LOGE(TAG, "Light '%s' not found in %d configured light(s)", light_id.c_str(), (int)lights_.size());
    return nullptr;
}

static bool query_and_match_service(const char *service, const char *proto, const std::string &target_id, std::string &out_ip, uint16_t &out_port) {
    std::string target_upper = target_id;
    for (auto &c : target_upper) c = toupper((unsigned char)c);
    if (target_upper.find(".LOCAL") != std::string::npos) {
        target_upper = target_upper.substr(0, target_upper.find(".LOCAL"));
    }

    mdns_result_t *results = nullptr;
    esp_err_t err = mdns_query_ptr(service, proto, 2000, 20, &results);
    if (err == ESP_OK && results) {
        mdns_result_t *r = results;
        while (r) {
            std::string inst = r->instance_name ? r->instance_name : "";
            std::string inst_upper = inst;
            for (auto &c : inst_upper) c = toupper((unsigned char)c);

            bool match = false;
            if (inst_upper == target_upper ||
                inst_upper.find(target_upper) != std::string::npos ||
                target_upper.find(inst_upper) != std::string::npos) {
                match = true;
            }

            for (size_t t = 0; t < r->txt_count && !match; t++) {
                std::string key = r->txt[t].key ? r->txt[t].key : "";
                std::string val = r->txt[t].value ? r->txt[t].value : "";
                std::string val_upper = val;
                for (auto &c : val_upper) c = toupper((unsigned char)c);
                if ((key == "id" || key == "eui64" || key == "eui") &&
                    (val_upper == target_upper || val_upper.find(target_upper) != std::string::npos)) {
                    match = true;
                    break;
                }
            }

            if (match) {
                mdns_ip_addr_t *a = r->addr;
                while (a) {
                    char ip_buf[INET_ADDRSTRLEN];
                    if (a->addr.type == ESP_IPADDR_TYPE_V4) {
                        inet_ntop(AF_INET, &(a->addr.u_addr.ip4), ip_buf, sizeof(ip_buf));
                        out_ip = ip_buf;
                        if (r->port != 0) out_port = r->port;
                        mdns_query_results_free(results);
                        return true;
                    }
                    a = a->next;
                }
            }
            r = r->next;
        }
        mdns_query_results_free(results);
    }
    return false;
}

bool NanoleafWifiComponent::resolve_host(NanoleafWifiLight &light) {
    if (!light.resolved_ip.empty()) {
        return true;
    }

    // 1. Fast check: if host is already an IPv4 literal
    struct in_addr dummy;
    if (inet_pton(AF_INET, light.host.c_str(), &dummy) == 1) {
        light.resolved_ip = light.host;
        return true;
    }

    // 2. Initialize mDNS
    esp_err_t m_err = mdns_init();
    if (m_err != ESP_OK && m_err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "mdns_init: %d", m_err);
    }

    // 3. Query mDNS services (_nanoleafapi._tcp and _ltpdu._tcp)
    std::string ip_found;
    uint16_t port_found = light.port;
    if (query_and_match_service("_nanoleafapi", "_tcp", light.host, ip_found, port_found) ||
        query_and_match_service("_ltpdu", "_tcp", light.host, ip_found, port_found) ||
        query_and_match_service("_nanoleafapi", "_tcp", light.id, ip_found, port_found) ||
        query_and_match_service("_ltpdu", "_tcp", light.id, ip_found, port_found)) {
        light.resolved_ip = ip_found;
        light.port = port_found;
        ESP_LOGI(TAG, "mDNS resolved '%s' -> %s:%d", light.host.c_str(), light.resolved_ip.c_str(), light.port);
        return true;
    }

    // 4. mDNS A-record query for .local hostname
    auto dot_local = light.host.find(".local");
    if (dot_local != std::string::npos) {
        std::string hostname = light.host.substr(0, dot_local);
        esp_ip4_addr_t addr;
        addr.addr = 0;
        esp_err_t err = mdns_query_a(hostname.c_str(), 1000, &addr);
        if (err == ESP_OK && addr.addr != 0) {
            char ip_buf[INET_ADDRSTRLEN];
            esp_ip4addr_ntoa(&addr, ip_buf, sizeof(ip_buf));
            light.resolved_ip = ip_buf;
            ESP_LOGI(TAG, "mDNS A-record resolved '%s' -> %s", light.host.c_str(), light.resolved_ip.c_str());
            return true;
        }
        ESP_LOGW(TAG, "Could not resolve mDNS device '%s'", light.host.c_str());
        return false;
    }

    // 5. Fallback: unicast standard DNS query
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
        ESP_LOGI(TAG, "DNS resolved '%s' -> %s", light.host.c_str(), light.resolved_ip.c_str());
        return true;
    }

    ESP_LOGW(TAG, "Failed to resolve hostname '%s'", light.host.c_str());
    return false;
}

bool NanoleafWifiComponent::http_put_state(NanoleafWifiLight &light, const std::string &json_payload, const char *action_name) {
    if (light.auth_token.empty()) {
        ESP_LOGE(TAG, "Cannot execute %s on '%s': no auth_token configured", action_name, light.id.c_str());
        return false;
    }
    if (light.resolved_ip.empty() && !resolve_host(light)) {
        return false;
    }

    int sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket() failed: errno %d", errno);
        return false;
    }

    struct timeval tv{ .tv_sec = 2, .tv_usec = 0 };
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(light.port);
    inet_pton(AF_INET, light.resolved_ip.c_str(), &addr.sin_addr);

    if (::connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "TCP connect to %s:%d failed: errno %d (device offline)", light.resolved_ip.c_str(), light.port, errno);
        ::close(sock);
        return false;
    }

    std::string req = "PUT /api/v1/" + light.auth_token + "/state HTTP/1.1\r\n" +
                      "Host: " + light.host + "\r\n" +
                      "Content-Type: application/json\r\n" +
                      "Content-Length: " + std::to_string(json_payload.length()) + "\r\n" +
                      "Connection: close\r\n\r\n" +
                      json_payload;

    ::send(sock, req.c_str(), req.length(), 0);

    char resp[256];
    int n = ::recv(sock, resp, sizeof(resp) - 1, 0);
    ::close(sock);

    if (n > 0) {
        resp[n] = '\0';
        std::string s(resp);
        if (s.find("204 No Content") != std::string::npos || s.find("200 OK") != std::string::npos) {
            ESP_LOGI(TAG, "Light '%s' -> %s (HTTP 204 Success)", light.id.c_str(), action_name);
            return true;
        } else if (s.find("401 Unauthorized") != std::string::npos) {
            ESP_LOGE(TAG, "Light '%s' rejected auth token (HTTP 401 Unauthorized)", light.id.c_str());
            return false;
        }
        ESP_LOGW(TAG, "Light '%s' returned status:\n%s", light.id.c_str(), resp);
        return false;
    }

    ESP_LOGW(TAG, "No HTTP response from %s:%d for %s", light.resolved_ip.c_str(), light.port, action_name);
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

bool NanoleafWifiComponent::activate_extcontrol(NanoleafWifiLight &light) {
    if (light.auth_token.empty()) {
        ESP_LOGE(TAG, "Cannot activate extControl: no auth_token for light '%s'", light.id.c_str());
        return false;
    }
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
            ESP_LOGI(TAG, "extControl mode successfully activated on light '%s' (%s)",
                     light.id.c_str(), light.resolved_ip.c_str());
            return true;
        }
        ESP_LOGW(TAG, "extControl activation returned error:\n%s", resp);
    }
    return false;
}

void NanoleafWifiComponent::queue_command(const HttpCommand &cmd) {
    if (!network::is_connected() || cmd_queue_ == nullptr) return;
    xQueueSend(cmd_queue_, &cmd, 0);
}

void NanoleafWifiComponent::send_on(const std::string &light_id, uint8_t r, uint8_t g, uint8_t b, uint8_t w, uint32_t transition_ms) {
    HttpCommand cmd;
    cmd.light_id = light_id;
    cmd.type = HttpCmdType::ON;
    cmd.r = r;
    cmd.g = g;
    cmd.b = b;
    cmd.transition_ms = transition_ms;
    queue_command(cmd);
}

void NanoleafWifiComponent::send_off(const std::string &light_id, uint32_t transition_ms) {
    HttpCommand cmd;
    cmd.light_id = light_id;
    cmd.type = HttpCmdType::OFF;
    cmd.transition_ms = transition_ms;
    queue_command(cmd);
}

void NanoleafWifiComponent::set_color(const std::string &light_id, uint8_t r, uint8_t g, uint8_t b, uint8_t w, uint32_t transition_ms) {
    HttpCommand cmd;
    cmd.light_id = light_id;
    cmd.type = HttpCmdType::COLOR;
    cmd.r = r;
    cmd.g = g;
    cmd.b = b;
    cmd.transition_ms = transition_ms;
    queue_command(cmd);
}

void NanoleafWifiComponent::set_brightness(const std::string &light_id, uint8_t brightness, uint32_t transition_ms) {
    HttpCommand cmd;
    cmd.light_id = light_id;
    cmd.type = HttpCmdType::BRIGHTNESS;
    cmd.brightness = brightness > 100 ? 100 : brightness;
    cmd.transition_ms = transition_ms;
    queue_command(cmd);
}

void NanoleafWifiComponent::set_color_temperature(const std::string &light_id, uint16_t color_temp, uint32_t transition_ms) {
    HttpCommand cmd;
    cmd.light_id = light_id;
    cmd.type = HttpCmdType::COLOR_TEMP;
    cmd.color_temp = color_temp;
    cmd.transition_ms = transition_ms;
    queue_command(cmd);
}

void NanoleafWifiComponent::worker_task(void *pvParameters) {
    auto *self = static_cast<NanoleafWifiComponent *>(pvParameters);
    HttpCommand cmd;

    while (true) {
        if (xQueueReceive(self->cmd_queue_, &cmd, portMAX_DELAY) == pdTRUE) {
            auto *light = self->find_light(cmd.light_id);
            if (!light) continue;

            std::string payload;
            const char *action_name = "State Update";

            switch (cmd.type) {
                case HttpCmdType::ON:
                    action_name = "Turn ON";
                    payload = "{\"on\":{\"value\":true}}";
                    break;

                case HttpCmdType::OFF:
                    action_name = "Turn OFF";
                    payload = "{\"on\":{\"value\":false}}";
                    break;

                case HttpCmdType::COLOR: {
                    action_name = "Set Color";
                    uint16_t hue = 0;
                    uint8_t sat = 0;
                    rgb_to_hs(cmd.r, cmd.g, cmd.b, hue, sat);
                    payload = "{\"on\":{\"value\":true},\"hue\":{\"value\":" + std::to_string(hue) +
                              "},\"sat\":{\"value\":" + std::to_string(sat) + "}}";
                    break;
                }

                case HttpCmdType::BRIGHTNESS:
                    action_name = "Set Brightness";
                    payload = "{\"on\":{\"value\":true},\"brightness\":{\"value\":" +
                              std::to_string(cmd.brightness) + "}}";
                    break;

                case HttpCmdType::COLOR_TEMP:
                    action_name = "Set Color Temperature";
                    payload = "{\"on\":{\"value\":true},\"ct\":{\"value\":" +
                              std::to_string(cmd.color_temp) + "}}";
                    break;
            }

            self->http_put_state(*light, payload, action_name);
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }
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

    if (!ctx->parent->resolve_host(*light)) {
        ESP_LOGE(TAG, "Could not resolve hostname '%s'", light->host.c_str());
        delete ctx;
        vTaskDelete(nullptr);
        return;
    }

    ctx->parent->activate_extcontrol(*light);
    delete ctx;
    vTaskDelete(nullptr);
}

void NanoleafWifiComponent::enable_extcontrol(const std::string &light_id, const std::string &override_auth_token) {
    auto *ctx = new ProvisionContext{this, light_id, override_auth_token};
    BaseType_t res = xTaskCreate(extcontrol_task, "nl_extctrl", 4096, ctx, tskIDLE_PRIORITY + 1, nullptr);
    if (res != pdPASS) {
        ESP_LOGE(TAG, "Failed to create extcontrol background task (error %d)", res);
        delete ctx;
    }
}

}  // namespace nanoleaf_wifi
}  // namespace esphome
