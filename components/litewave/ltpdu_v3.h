#pragma once

#include <cstdint>
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>
#include <functional>

#include "esphome/core/log.h"

#include "mbedtls/bignum.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/ccm.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "esp_random.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

namespace esphome {
namespace litewave {

static const char *const LTPDU_TAG = "litewave.ltpdu";

// ---------------------------------------------------------------------------
// TLV helpers (Auth TLV: 1B tag + 2B BE length; LTPDU TLV: 2B tag + 2B len)
// ---------------------------------------------------------------------------

inline void auth_tlv_append(std::vector<uint8_t> &buf, uint8_t tag,
                            const uint8_t *val, uint16_t len) {
    buf.push_back(tag);
    buf.push_back((len >> 8) & 0xFF);
    buf.push_back(len & 0xFF);
    buf.insert(buf.end(), val, val + len);
}

inline void auth_tlv_append(std::vector<uint8_t> &buf, uint8_t tag,
                            const std::vector<uint8_t> &val) {
    auth_tlv_append(buf, tag, val.data(), val.size());
}

struct AuthTlv {
    uint8_t tag;
    std::vector<uint8_t> value;
};

inline std::vector<AuthTlv> parse_auth_tlvs(const uint8_t *data, size_t len) {
    std::vector<AuthTlv> result;
    size_t offset = 0;
    while (offset + 3 <= len) {
        uint8_t tag = data[offset];
        uint16_t vlen = (data[offset + 1] << 8) | data[offset + 2];
        if (offset + 3 + vlen > len) break;
        result.push_back({tag, {data + offset + 3, data + offset + 3 + vlen}});
        offset += 3 + vlen;
    }
    return result;
}

inline const std::vector<uint8_t> *find_auth_tlv(
    const std::vector<AuthTlv> &tlvs, uint8_t tag) {
    for (const auto &t : tlvs) {
        if (t.tag == tag) return &t.value;
    }
    return nullptr;
}

// LTPDU command TLV (2B tag + 2B length)
inline std::vector<uint8_t> build_ltpdu_cmd(const std::string &endpoint,
                                            const uint8_t *value, size_t vlen,
                                            uint8_t method) {
    std::vector<uint8_t> buf;
    // Tag 1: endpoint
    uint16_t elen = endpoint.size();
    buf.push_back(0); buf.push_back(1);
    buf.push_back((elen >> 8) & 0xFF); buf.push_back(elen & 0xFF);
    buf.insert(buf.end(), endpoint.begin(), endpoint.end());
    // Tag 2: payload
    buf.push_back(0); buf.push_back(2);
    buf.push_back((vlen >> 8) & 0xFF); buf.push_back(vlen & 0xFF);
    if (value && vlen > 0) buf.insert(buf.end(), value, value + vlen);
    // Tag 4: method
    buf.push_back(0); buf.push_back(4);
    buf.push_back(0); buf.push_back(1);
    buf.push_back(method);
    return buf;
}

struct LtpduResponse {
    std::string endpoint;
    int status;
    std::vector<uint8_t> value;
};

inline LtpduResponse parse_ltpdu_response(const uint8_t *data, size_t len) {
    LtpduResponse r;
    r.status = -1;
    size_t offset = 0;
    while (offset + 4 <= len) {
        uint16_t tag = (data[offset] << 8) | data[offset + 1];
        uint16_t vlen = (data[offset + 2] << 8) | data[offset + 3];
        const uint8_t *v = data + offset + 4;
        if (offset + 4 + vlen > len) break;
        if (tag == 1) {
            r.endpoint.assign(reinterpret_cast<const char *>(v), vlen);
        } else if (tag == 3 && vlen >= 1) {
            r.status = v[0];
            r.value.assign(v + 1, v + vlen);
        } else if (tag == 2) {
            r.value.assign(v, v + vlen);
        }
        offset += 4 + vlen;
    }
    return r;
}

// ---------------------------------------------------------------------------
// V3 binary framing
// ---------------------------------------------------------------------------

inline std::vector<uint8_t> build_v3_request(uint16_t msg_id, uint16_t client_id,
                                             uint8_t uri_type, uint8_t method,
                                             const std::vector<uint8_t> &data) {
    std::vector<uint8_t> pkt(12 + data.size());
    pkt[0] = 0x01; // version
    pkt[1] = 0x01; // Request
    pkt[2] = (msg_id >> 8) & 0xFF; pkt[3] = msg_id & 0xFF;
    pkt[4] = (client_id >> 8) & 0xFF; pkt[5] = client_id & 0xFF;
    pkt[6] = uri_type;
    pkt[7] = method;
    uint32_t dlen = data.size();
    pkt[8] = (dlen >> 24) & 0xFF; pkt[9] = (dlen >> 16) & 0xFF;
    pkt[10] = (dlen >> 8) & 0xFF; pkt[11] = dlen & 0xFF;
    memcpy(pkt.data() + 12, data.data(), data.size());
    return pkt;
}

struct V3Response {
    uint8_t version;
    uint8_t msg_type;
    uint16_t msg_id;
    uint16_t client_id;
    uint8_t resp_code;
    std::vector<uint8_t> data;
    bool valid;
};

inline V3Response parse_v3_response(const uint8_t *raw, size_t len) {
    V3Response r{};
    r.valid = false;
    if (len < 6) return r;
    r.version = raw[0];
    r.msg_type = raw[1];
    if (r.msg_type == 5) { // Ack
        r.msg_id = (raw[2] << 8) | raw[3];
        r.client_id = (raw[4] << 8) | raw[5];
        r.resp_code = 0;
        r.valid = true;
        return r;
    }
    if (len < 12) return r;
    r.msg_id = (raw[2] << 8) | raw[3];
    r.client_id = (raw[4] << 8) | raw[5];
    r.resp_code = raw[6]; // actually uri_type position in response maps to resp_code
    uint32_t dlen = (raw[8] << 24) | (raw[9] << 16) | (raw[10] << 8) | raw[11];
    if (12 + dlen > len) dlen = len - 12;
    r.data.assign(raw + 12, raw + 12 + dlen);
    r.valid = true;
    return r;
}

// ---------------------------------------------------------------------------
// SHA-256 helpers
// ---------------------------------------------------------------------------

inline void sha256_multi(uint8_t out[32], const std::vector<std::pair<const uint8_t *, size_t>> &parts) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    for (const auto &p : parts) {
        mbedtls_sha256_update(&ctx, p.first, p.second);
    }
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
}

inline void sha256(uint8_t out[32], const uint8_t *data, size_t len) {
    sha256_multi(out, {{data, len}});
}

// Convert mbedtls_mpi to big-endian byte vector (minimal length, no leading zeros)
inline std::vector<uint8_t> mpi_to_bytes(const mbedtls_mpi &m) {
    size_t len = mbedtls_mpi_size(&m);
    if (len == 0) return {0};
    std::vector<uint8_t> buf(len);
    mbedtls_mpi_write_binary(&m, buf.data(), len);
    return buf;
}

inline void mpi_from_bytes(mbedtls_mpi &m, const uint8_t *data, size_t len) {
    mbedtls_mpi_read_binary(&m, data, len);
}

// H(parts...) -> int (as mpi)
inline void sha256_to_mpi(mbedtls_mpi &out,
                          const std::vector<std::pair<const uint8_t *, size_t>> &parts) {
    uint8_t hash[32];
    sha256_multi(hash, parts);
    mpi_from_bytes(out, hash, 32);
}

// ---------------------------------------------------------------------------
// SRP-6a Client (SHA-256, g=2, 512-bit N — matches APK)
// ---------------------------------------------------------------------------

// 512-bit prime from APK
static const char *SRP_N_512_DEC =
    "11229916235553671384460957561912561881437004243772597012148068303101566041140"
    "271835868089403470930092847368898606170616536123073256223246414212750058495475";

class SRP6aClient {
 public:
    SRP6aClient(const std::string &username, const uint8_t *password, size_t pw_len) {
        username_ = username;
        password_.assign(password, password + pw_len);
        mbedtls_mpi_init(&N_); mbedtls_mpi_init(&g_);
        mbedtls_mpi_init(&a_); mbedtls_mpi_init(&A_);
        mbedtls_mpi_init(&B_); mbedtls_mpi_init(&salt_);
        mbedtls_mpi_read_string(&N_, 10, SRP_N_512_DEC);
        mbedtls_mpi_lset(&g_, 2);
        // Generate random a (64 bytes)
        uint8_t rand_buf[64];
        esp_fill_random(rand_buf, sizeof(rand_buf));
        mpi_from_bytes(a_, rand_buf, 64);
        // A = g^a mod N
        mbedtls_mpi_exp_mod(&A_, &g_, &a_, &N_, nullptr);
    }

    ~SRP6aClient() {
        mbedtls_mpi_free(&N_); mbedtls_mpi_free(&g_);
        mbedtls_mpi_free(&a_); mbedtls_mpi_free(&A_);
        mbedtls_mpi_free(&B_); mbedtls_mpi_free(&salt_);
    }

    std::vector<uint8_t> get_public_key_bytes() { return mpi_to_bytes(A_); }

    // Process server challenge, return M1 proof
    std::vector<uint8_t> process_challenge(const uint8_t *salt_data, size_t salt_len,
                                           const uint8_t *B_data, size_t B_len) {
        mpi_from_bytes(salt_, salt_data, salt_len);
        mpi_from_bytes(B_, B_data, B_len);

        auto N_bytes = mpi_to_bytes(N_);
        auto g_bytes = mpi_to_bytes(g_);
        auto A_bytes = mpi_to_bytes(A_);
        auto B_bytes = mpi_to_bytes(B_);
        auto salt_bytes = mpi_to_bytes(salt_);

        // k = H(N || g)
        mbedtls_mpi k;
        mbedtls_mpi_init(&k);
        sha256_to_mpi(k, {{N_bytes.data(), N_bytes.size()},
                          {g_bytes.data(), g_bytes.size()}});

        // u = H(A || B)
        mbedtls_mpi u;
        mbedtls_mpi_init(&u);
        sha256_to_mpi(u, {{A_bytes.data(), A_bytes.size()},
                          {B_bytes.data(), B_bytes.size()}});

        // x = H(salt || H(username || ':' || password))
        uint8_t inner_hash[32];
        {
            mbedtls_sha256_context ctx;
            mbedtls_sha256_init(&ctx);
            mbedtls_sha256_starts(&ctx, 0);
            mbedtls_sha256_update(&ctx, (const uint8_t *)username_.c_str(), username_.size());
            uint8_t colon = ':';
            mbedtls_sha256_update(&ctx, &colon, 1);
            mbedtls_sha256_update(&ctx, password_.data(), password_.size());
            mbedtls_sha256_finish(&ctx, inner_hash);
            mbedtls_sha256_free(&ctx);
        }
        mbedtls_mpi x;
        mbedtls_mpi_init(&x);
        sha256_to_mpi(x, {{salt_bytes.data(), salt_bytes.size()},
                          {inner_hash, 32}});

        // S = (B - k * g^x)^(a + u*x) mod N
        mbedtls_mpi gx, kgx, base, ux, exp, S;
        mbedtls_mpi_init(&gx); mbedtls_mpi_init(&kgx);
        mbedtls_mpi_init(&base); mbedtls_mpi_init(&ux);
        mbedtls_mpi_init(&exp); mbedtls_mpi_init(&S);

        mbedtls_mpi_exp_mod(&gx, &g_, &x, &N_, nullptr);  // g^x mod N
        mbedtls_mpi_mul_mpi(&kgx, &k, &gx);               // k * g^x
        mbedtls_mpi_mod_mpi(&kgx, &kgx, &N_);             // mod N
        mbedtls_mpi_sub_mpi(&base, &B_, &kgx);            // B - k*g^x
        // Ensure positive
        if (mbedtls_mpi_cmp_int(&base, 0) < 0)
            mbedtls_mpi_add_mpi(&base, &base, &N_);
        mbedtls_mpi_mod_mpi(&base, &base, &N_);

        mbedtls_mpi_mul_mpi(&ux, &u, &x);                 // u*x
        mbedtls_mpi_add_mpi(&exp, &a_, &ux);              // a + u*x

        mbedtls_mpi_exp_mod(&S, &base, &exp, &N_, nullptr); // S = base^exp mod N

        auto S_bytes = mpi_to_bytes(S);

        // session_key_ = H(S)
        sha256(session_key_, S_bytes.data(), S_bytes.size());

        // M1 = H(H(N) XOR H(g) || H(username) || salt || A || B || K)
        uint8_t hN[32], hg[32], hNxg[32], hu[32];
        sha256(hN, N_bytes.data(), N_bytes.size());
        sha256(hg, g_bytes.data(), g_bytes.size());
        for (int i = 0; i < 32; i++) hNxg[i] = hN[i] ^ hg[i];
        sha256(hu, (const uint8_t *)username_.c_str(), username_.size());

        sha256_multi(M1_, {
            {hNxg, 32}, {hu, 32},
            {salt_bytes.data(), salt_bytes.size()},
            {A_bytes.data(), A_bytes.size()},
            {B_bytes.data(), B_bytes.size()},
            {session_key_, 32},
        });

        mbedtls_mpi_free(&k); mbedtls_mpi_free(&u); mbedtls_mpi_free(&x);
        mbedtls_mpi_free(&gx); mbedtls_mpi_free(&kgx); mbedtls_mpi_free(&base);
        mbedtls_mpi_free(&ux); mbedtls_mpi_free(&exp); mbedtls_mpi_free(&S);

        return {M1_, M1_ + 32};
    }

    bool verify_server_proof(const uint8_t *M2, size_t M2_len) {
        auto A_bytes = mpi_to_bytes(A_);
        uint8_t expected[32];
        sha256_multi(expected, {
            {A_bytes.data(), A_bytes.size()},
            {M1_, 32},
            {session_key_, 32},
        });
        return M2_len == 32 && memcmp(M2, expected, 32) == 0;
    }

    // H(H(S)) per APK getSessionKey()
    void get_session_key(uint8_t out[32]) {
        sha256(out, session_key_, 32);
    }

 private:
    std::string username_;
    std::vector<uint8_t> password_;
    mbedtls_mpi N_, g_, a_, A_, B_, salt_;
    uint8_t session_key_[32]{};
    uint8_t M1_[32]{};
};

// ---------------------------------------------------------------------------
// Encrypted sessions
// ---------------------------------------------------------------------------

class CrcEncryptedSession {
 public:
    CrcEncryptedSession(const uint8_t key[16], const uint8_t iv[16]) {
        mbedtls_aes_init(&enc_ctx_);
        mbedtls_aes_init(&dec_ctx_);
        mbedtls_aes_setkey_enc(&enc_ctx_, key, 128);
        mbedtls_aes_setkey_enc(&dec_ctx_, key, 128);
        memcpy(enc_nonce_, iv, 16);
        memcpy(dec_nonce_, iv, 16);
        enc_offset_ = 0;
        dec_offset_ = 0;
        memset(enc_stream_, 0, 16);
        memset(dec_stream_, 0, 16);
    }

    ~CrcEncryptedSession() {
        mbedtls_aes_free(&enc_ctx_);
        mbedtls_aes_free(&dec_ctx_);
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &data) {
        // Keep decrypt counter in sync
        std::vector<uint8_t> dummy(data.size());
        mbedtls_aes_crypt_ctr(&dec_ctx_, data.size(), &dec_offset_,
                              dec_nonce_, dec_stream_,
                              data.data(), dummy.data());
        std::vector<uint8_t> out(data.size());
        mbedtls_aes_crypt_ctr(&enc_ctx_, data.size(), &enc_offset_,
                              enc_nonce_, enc_stream_,
                              data.data(), out.data());
        return out;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &data) {
        // Keep encrypt counter in sync
        std::vector<uint8_t> dummy(data.size());
        mbedtls_aes_crypt_ctr(&enc_ctx_, data.size(), &enc_offset_,
                              enc_nonce_, enc_stream_,
                              data.data(), dummy.data());
        std::vector<uint8_t> out(data.size());
        mbedtls_aes_crypt_ctr(&dec_ctx_, data.size(), &dec_offset_,
                              dec_nonce_, dec_stream_,
                              data.data(), out.data());
        return out;
    }

 private:
    mbedtls_aes_context enc_ctx_, dec_ctx_;
    uint8_t enc_nonce_[16], dec_nonce_[16];
    uint8_t enc_stream_[16], dec_stream_[16];
    size_t enc_offset_, dec_offset_;
};

class CcmEncryptedSession {
 public:
    CcmEncryptedSession(const uint8_t key[16], const uint8_t *iv_base,
                        int iv_size, uint64_t initial_counter = 0)
        : iv_size_(iv_size), counter_(initial_counter) {
        mbedtls_ccm_init(&ctx_);
        mbedtls_ccm_setkey(&ctx_, MBEDTLS_CIPHER_ID_AES, key, 128);
        memcpy(iv_base_, iv_base, 8);
    }

    ~CcmEncryptedSession() {
        mbedtls_ccm_free(&ctx_);
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &data) {
        uint8_t nonce[13];
        build_iv(nonce);
        std::vector<uint8_t> out(data.size() + 4); // 4-byte tag
        mbedtls_ccm_encrypt_and_tag(&ctx_, data.size(), nonce, iv_size_,
                                    nullptr, 0, data.data(),
                                    out.data(), out.data() + data.size(), 4);
        return out;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &data) {
        if (data.size() < 4) return {};
        uint8_t nonce[13];
        build_iv(nonce);
        size_t plain_len = data.size() - 4;
        std::vector<uint8_t> out(plain_len);
        int ret = mbedtls_ccm_auth_decrypt(&ctx_, plain_len, nonce, iv_size_,
                                           nullptr, 0, data.data(),
                                           out.data(),
                                           data.data() + plain_len, 4);
        if (ret != 0) {
            ESP_LOGW(LTPDU_TAG, "CCM decrypt failed: %d", ret);
            return {};
        }
        return out;
    }

 private:
    void build_iv(uint8_t *iv) {
        memset(iv, 0, iv_size_);
        uint8_t cb[8];
        for (int i = 7; i >= 0; i--) {
            cb[i] = counter_ & 0xFF;
            counter_ >>= 8;
        }
        // Reconstruct counter for next call (it was just consumed)
        uint64_t saved = 0;
        for (int i = 0; i < 8; i++) saved = (saved << 8) | cb[i];
        counter_ = saved + 1;

        if (iv_size_ == 13) {
            memcpy(iv, cb + 3, 5);
            memcpy(iv + 5, iv_base_, 8);
        } else if (iv_size_ == 12) {
            memcpy(iv, cb + 4, 4);
            memcpy(iv + 4, iv_base_, 8);
        }
    }

    mbedtls_ccm_context ctx_;
    uint8_t iv_base_[8];
    int iv_size_;
    uint64_t counter_;
};

// Polymorphic session interface
class EncryptedSession {
 public:
    virtual ~EncryptedSession() = default;
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t> &data) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t> &data) = 0;
};

class CrcSessionWrapper : public EncryptedSession {
 public:
    CrcSessionWrapper(const uint8_t key[16], const uint8_t iv[16]) : s_(key, iv) {}
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &data) override { return s_.encrypt(data); }
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &data) override { return s_.decrypt(data); }
 private:
    CrcEncryptedSession s_;
};

class CcmSessionWrapper : public EncryptedSession {
 public:
    CcmSessionWrapper(const uint8_t key[16], const uint8_t *iv_base, int iv_size)
        : s_(key, iv_base, iv_size) {}
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &data) override { return s_.encrypt(data); }
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &data) override { return s_.decrypt(data); }
 private:
    CcmEncryptedSession s_;
};

inline EncryptedSession *create_session(const uint8_t session_key[32],
                                        uint8_t ver_major, uint8_t ver_minor) {
    uint8_t aes_key[16];
    memcpy(aes_key, session_key, 16);

    if (ver_major == 3 && ver_minor == 0) {
        uint8_t iv[16];
        memset(iv, 0, 8);
        memcpy(iv + 8, session_key + 16, 8);
        return new CrcSessionWrapper(aes_key, iv);
    } else if (ver_major == 3 && ver_minor == 1) {
        return new CcmSessionWrapper(aes_key, session_key + 16, 13);
    } else if (ver_major == 3 && ver_minor == 2) {
        return new CcmSessionWrapper(aes_key, session_key + 16, 12);
    }
    ESP_LOGE(LTPDU_TAG, "Unknown session version %d.%d", ver_major, ver_minor);
    return nullptr;
}

// ---------------------------------------------------------------------------
// Auth tags (from APK)
// ---------------------------------------------------------------------------
enum AuthTagEnum : uint8_t {
    AUTH_TYPE = 0x01,
    SALT = 0x02,
    PUBLIC_KEY = 0x03,
    VERIFICATION = 0x04,
    AUTH_TOKEN_REQUEST = 0x05,
    AUTH_TOKEN_RESPONSE = 0x06,
    SESSION_TYPE = 0x07,
    DISCONNECT = 0x08,
    UNPAIR = 0x09,
    SESSION_VERSION = 0x11,
    AUTH_ERROR = 0xF0,
};

inline const char *describe_ltpdu_code(uint8_t code) {
    switch (code) {
        case 0: return "OK";
        case 1: return "No Content";
        case 2: return "Bad Request";
        case 3: return "Unauthorized (invalid pairing code)";
        case 4: return "Payload Too Large";
        case 5: return "Pairing Slots Full (light needs factory reset - power cycle 5 times)";
        case 6: return "Forbidden (admin key claim needed)";
        default: return "Unknown Error";
    }
}

// ---------------------------------------------------------------------------
// UDP transport
// ---------------------------------------------------------------------------

class UdpTransport {
 public:
    UdpTransport(const std::string &host, uint16_t port, float timeout_s = 8.0f)
        : host_(host), port_(port), timeout_s_(timeout_s), sock_(-1) {}

    ~UdpTransport() { close(); }

    bool open() {
        bool is_ipv6 = host_.find(':') != std::string::npos;
        int family = is_ipv6 ? AF_INET6 : AF_INET;
        sock_ = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_ < 0) {
            ESP_LOGE(LTPDU_TAG, "socket() failed: %d", errno);
            return false;
        }

        struct timeval tv;
        tv.tv_sec = (int)timeout_s_;
        tv.tv_usec = (int)((timeout_s_ - tv.tv_sec) * 1000000);
        ::setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        if (is_ipv6) {
            struct sockaddr_in6 local_addr6{};
            local_addr6.sin6_family = AF_INET6;
            local_addr6.sin6_port = htons(0);
            local_addr6.sin6_addr = in6addr_any;
            ::bind(sock_, (struct sockaddr *)&local_addr6, sizeof(local_addr6));

            memset(&addr6_, 0, sizeof(addr6_));
            addr6_.sin6_family = AF_INET6;
            addr6_.sin6_port = htons(port_);
            if (inet_pton(AF_INET6, host_.c_str(), &addr6_.sin6_addr) <= 0) {
                struct addrinfo hints{}, *res = nullptr;
                hints.ai_family = AF_INET6;
                hints.ai_socktype = SOCK_DGRAM;
                if (getaddrinfo(host_.c_str(), nullptr, &hints, &res) == 0 && res) {
                    memcpy(&addr6_, res->ai_addr, sizeof(addr6_));
                    addr6_.sin6_port = htons(port_);
                    freeaddrinfo(res);
                } else {
                    ESP_LOGE(LTPDU_TAG, "Failed to resolve IPv6 host '%s'", host_.c_str());
                    close();
                    return false;
                }
            }
        } else {
            memset(&addr4_, 0, sizeof(addr4_));
            addr4_.sin_family = AF_INET;
            addr4_.sin_port = htons(port_);
            if (inet_pton(AF_INET, host_.c_str(), &addr4_.sin_addr) <= 0) {
                struct hostent *he = gethostbyname(host_.c_str());
                if (he && he->h_addr_list && he->h_addr_list[0]) {
                    memcpy(&addr4_.sin_addr, he->h_addr_list[0], sizeof(addr4_.sin_addr));
                } else {
                    ESP_LOGE(LTPDU_TAG, "Failed to resolve host '%s'", host_.c_str());
                    close();
                    return false;
                }
            }
        }
        is_ipv6_ = is_ipv6;
        return true;
    }

    int send_recv(const uint8_t *data, size_t len,
                  uint8_t *resp_buf, size_t resp_max, int retries = 6) {
        struct sockaddr *addr = is_ipv6_ ? (struct sockaddr *)&addr6_
                                         : (struct sockaddr *)&addr4_;
        socklen_t addr_len = is_ipv6_ ? sizeof(addr6_) : sizeof(addr4_);

        for (int attempt = 0; attempt < retries; attempt++) {
            ssize_t sent = ::sendto(sock_, data, len, 0, addr, addr_len);
            if (sent < 0) {
                ESP_LOGE(LTPDU_TAG, "sendto() failed (errno=%d: %s)", errno, strerror(errno));
            } else {
                ESP_LOGD(LTPDU_TAG, "sendto() sent %d bytes to %s:%d", (int)sent, host_.c_str(), port_);
            }
            int n = ::recvfrom(sock_, resp_buf, resp_max, 0, nullptr, nullptr);
            if (n > 0) {
                ESP_LOGI(LTPDU_TAG, "recvfrom() received %d bytes from %s:%d", n, host_.c_str(), port_);
                return n;
            }
            ESP_LOGW(LTPDU_TAG, "UDP timeout (attempt %d/%d)", attempt + 1, retries);
        }
        return -1;
    }

    void close() {
        if (sock_ >= 0) {
            ::close(sock_);
            sock_ = -1;
        }
    }

 private:
    std::string host_;
    uint16_t port_;
    float timeout_s_;
    int sock_;
    bool is_ipv6_{false};
    struct sockaddr_in addr4_;
    struct sockaddr_in6 addr6_;
};

// ---------------------------------------------------------------------------
// LTPDU V3 session (full provisioning flow)
// ---------------------------------------------------------------------------

class LtpduV3Session {
 public:
    LtpduV3Session(const std::string &host, uint16_t port = 12566)
        : transport_(host, port) {
        client_id_ = 0xFFFF;
        msg_counter_ = esp_random() & 0xFFFE;
        if (msg_counter_ == 0) msg_counter_ = 1;
    }

    bool connect() { return transport_.open(); }

    bool pair(const std::string &service_name, const std::string &pairing_code) {
        // Username = service name truncated at first hyphen
        std::string username = service_name;
        auto dash = username.find('-');
        if (dash != std::string::npos) {
            // Trim trailing spaces before the hyphen
            while (dash > 0 && username[dash - 1] == ' ') dash--;
            username = username.substr(0, dash);
        }

        // Password = digit VALUES (not ASCII)
        std::vector<uint8_t> password;
        for (char c : pairing_code) {
            if (c >= '0' && c <= '9') password.push_back(c - '0');
        }

        ESP_LOGI(LTPDU_TAG, "SRP auth as '%s'", username.c_str());

        SRP6aClient srp(username, password.data(), password.size());
        auto A_bytes = srp.get_public_key_bytes();

        // Step 1: send A + auth type
        std::vector<uint8_t> step1;
        auth_tlv_append(step1, PUBLIC_KEY, A_bytes.data(), A_bytes.size());
        uint8_t auth_type = 1; // PairingCode
        auth_tlv_append(step1, AUTH_TYPE, &auth_type, 1);
        uint8_t session_type = 2;
        auth_tlv_append(step1, SESSION_TYPE, &session_type, 1);

        auto resp1 = send_secure(step1);
        if (resp1.empty()) { ESP_LOGE(LTPDU_TAG, "Step 1: no response"); return false; }

        auto tlvs1 = parse_auth_tlvs(resp1.data(), resp1.size());
        auto *salt = find_auth_tlv(tlvs1, SALT);
        auto *B = find_auth_tlv(tlvs1, PUBLIC_KEY);
        auto *ver = find_auth_tlv(tlvs1, SESSION_VERSION);
        if (!salt || !B) { ESP_LOGE(LTPDU_TAG, "Step 1: missing salt/B"); return false; }

        uint8_t ver_major = 3, ver_minor = 0;
        if (ver && ver->size() >= 2) { ver_major = (*ver)[0]; ver_minor = (*ver)[1]; }

        // Step 2: compute M1
        auto M1 = srp.process_challenge(salt->data(), salt->size(), B->data(), B->size());

        std::vector<uint8_t> step2;
        auth_tlv_append(step2, VERIFICATION, M1.data(), M1.size());

        auto resp2 = send_secure(step2);
        if (resp2.empty()) { ESP_LOGE(LTPDU_TAG, "Step 2: no response"); return false; }

        auto tlvs2 = parse_auth_tlvs(resp2.data(), resp2.size());
        auto *err_tlv = find_auth_tlv(tlvs2, AUTH_ERROR);
        if (err_tlv && !err_tlv->empty()) {
            uint8_t err_code = (*err_tlv)[0];
            const char *err_msg = "Unknown error";
            if (err_code == 1) err_msg = "Client ID Not Found";
            else if (err_code == 2) err_msg = "Verification Failed (Incorrect pairing code or expired commissioning window)";
            else if (err_code == 3) err_msg = "Max Pairings Reached (All pairing slots on light are full — power cycle 5 times to reset)";
            else if (err_code == 4) err_msg = "Public Key Not Sent";
            else if (err_code == 5) err_msg = "Bad Request";
            else if (err_code == 6) err_msg = "Auth Token Not Found";
            ESP_LOGE(LTPDU_TAG, "Step 2 rejected by light: %s (code %d)", err_msg, err_code);
            return false;
        }

        auto *M2 = find_auth_tlv(tlvs2, VERIFICATION);
        if (!M2) { ESP_LOGE(LTPDU_TAG, "Step 2: missing M2"); return false; }
        if (!srp.verify_server_proof(M2->data(), M2->size())) {
            ESP_LOGE(LTPDU_TAG, "Step 2: server proof failed");
            return false;
        }

        // Create encrypted session
        uint8_t session_key[32];
        srp.get_session_key(session_key);
        session_ = create_session(session_key, ver_major, ver_minor);
        if (!session_) return false;

        // Step 3: get auth token
        std::vector<uint8_t> step3;
        auth_tlv_append(step3, AUTH_TOKEN_REQUEST, (const uint8_t *)"", 0);
        auto enc3 = session_->encrypt(step3);
        auto resp3 = send_secure(enc3);
        if (!resp3.empty()) {
            auto dec3 = session_->decrypt(resp3);
            auto tlvs3 = parse_auth_tlvs(dec3.data(), dec3.size());
            auto *token = find_auth_tlv(tlvs3, AUTH_TOKEN_RESPONSE);
            if (token) {
                auth_token_ = *token;
                ESP_LOGI(LTPDU_TAG, "Auth token received (%d bytes)", token->size());
            }
        }

        ESP_LOGI(LTPDU_TAG, "Authentication complete (v%d.%d)", ver_major, ver_minor);
        return true;
    }

    // GET an LTPDU endpoint
    LtpduResponse get(const std::string &endpoint) {
        return send_ltpdu(endpoint, nullptr, 0, 0);
    }

    // POST to an LTPDU endpoint
    LtpduResponse post(const std::string &endpoint, const uint8_t *value, size_t vlen) {
        return send_ltpdu(endpoint, value, vlen, 1);
    }

    // PUT to an LTPDU endpoint
    LtpduResponse put(const std::string &endpoint, const uint8_t *value, size_t vlen) {
        return send_ltpdu(endpoint, value, vlen, 2);
    }

    void unpair() {
        if (session_) {
            std::vector<uint8_t> unpair_tlv;
            auth_tlv_append(unpair_tlv, UNPAIR, (const uint8_t *)"", 0);
            auto enc = session_->encrypt(unpair_tlv);
            send_secure(enc); // best effort
            delete session_;
            session_ = nullptr;
        }
        transport_.close();
    }

    void disconnect() {
        if (session_) {
            std::vector<uint8_t> disc_tlv;
            auth_tlv_append(disc_tlv, DISCONNECT, (const uint8_t *)"", 0);
            auto enc = session_->encrypt(disc_tlv);
            send_secure(enc); // best effort
            delete session_;
            session_ = nullptr;
        }
        transport_.close();
    }

 private:
    uint16_t next_msg_id() { return msg_counter_++; }

    std::vector<uint8_t> send_secure(const std::vector<uint8_t> &data) {
        auto pkt = build_v3_request(next_msg_id(), client_id_, 1 /*Secure*/, 1 /*POST*/, data);
        uint8_t resp_buf[4096];
        int n = transport_.send_recv(pkt.data(), pkt.size(), resp_buf, sizeof(resp_buf));
        if (n <= 0) return {};
        auto resp = parse_v3_response(resp_buf, n);
        if (!resp.valid) return {};
        if (resp.resp_code != 0) {
            ESP_LOGE(LTPDU_TAG, "Secure request rejected: code %d (%s)",
                     resp.resp_code, describe_ltpdu_code(resp.resp_code));
            return {};
        }
        if (resp.client_id != 0xFFFF) client_id_ = resp.client_id;
        return resp.data;
    }

    LtpduResponse send_ltpdu(const std::string &endpoint,
                             const uint8_t *value, size_t vlen, uint8_t method) {
        if (!session_) return {"", -1, {}};
        auto payload = build_ltpdu_cmd(endpoint, value, vlen, method);
        auto enc = session_->encrypt(payload);
        auto pkt = build_v3_request(next_msg_id(), client_id_, 2 /*LTPDU*/, 1 /*POST*/, enc);
        uint8_t resp_buf[4096];
        int n = transport_.send_recv(pkt.data(), pkt.size(), resp_buf, sizeof(resp_buf));
        if (n <= 0) return {"", -1, {}};
        auto resp = parse_v3_response(resp_buf, n);
        if (!resp.valid || resp.data.empty()) return {"", -1, {}};
        auto dec = session_->decrypt(resp.data);
        return parse_ltpdu_response(dec.data(), dec.size());
    }

    UdpTransport transport_;
    uint16_t client_id_;
    uint16_t msg_counter_;
    EncryptedSession *session_{nullptr};
    std::vector<uint8_t> auth_token_;
};

// ---------------------------------------------------------------------------
// High-level provision function (runs in calling context)
// ---------------------------------------------------------------------------

inline bool provision_light_sync(const std::string &host,
                                 uint16_t port,
                                 const std::string &pairing_code,
                                 const std::string &service_name_hint,
                                 const uint8_t *shared_secret, size_t ss_len,
                                 uint16_t pan_id,
                                 uint8_t channel,
                                 uint16_t admin_key = 0,
                                 const uint8_t *acl_payload = nullptr,
                                 size_t acl_len = 0) {
    LtpduV3Session session(host, port);
    if (!session.connect()) {
        ESP_LOGE(LTPDU_TAG, "UDP connect failed to %s", host.c_str());
        return false;
    }

    // Use host as service name hint if nothing better
    std::string svc = service_name_hint.empty() ? host : service_name_hint;

    if (!session.pair(svc, pairing_code)) {
        ESP_LOGE(LTPDU_TAG, "SRP pairing failed");
        session.disconnect();
        return false;
    }

    // 1. Admin Key (if configured)
    if (admin_key != 0) {
        uint8_t admin_buf[2] = {static_cast<uint8_t>((admin_key >> 8) & 0xFF),
                                static_cast<uint8_t>(admin_key & 0xFF)};
        session.post("sp/admin", admin_buf, sizeof(admin_buf));
    }

    // 2. PAN ID
    uint8_t pan_buf[2] = {static_cast<uint8_t>((pan_id >> 8) & 0xFF),
                          static_cast<uint8_t>(pan_id & 0xFF)};
    session.post("sp/pi", pan_buf, sizeof(pan_buf));

    // 3. Channel
    session.post("sp/mc", &channel, 1);

    // 4. Shared Secret
    ESP_LOGI(LTPDU_TAG, "Writing sp/ss (%d bytes)...", ss_len);
    auto wr = session.post("sp/ss", shared_secret, ss_len);
    if (wr.status != 0 && wr.status != -1) {
        ESP_LOGW(LTPDU_TAG, "sp/ss write status: %d", wr.status);
    }

    // Verify readback
    auto rd = session.get("sp/ss");
    if (rd.status == 0 && rd.value.size() == ss_len &&
        memcmp(rd.value.data(), shared_secret, ss_len) == 0) {
        ESP_LOGI(LTPDU_TAG, "sp/ss verified!");
    } else {
        ESP_LOGW(LTPDU_TAG, "sp/ss readback mismatch (status=%d, len=%d)",
                 rd.status, rd.value.size());
    }

    // 5. Switch Access Control List (ACL)
    if (acl_payload && acl_len > 0) {
        ESP_LOGI(LTPDU_TAG, "Writing lb/0/sp/llc/acl (%d bytes)...", acl_len);
        auto wr_acl = session.put("lb/0/sp/llc/acl", acl_payload, acl_len);
        if (wr_acl.status != 0 && wr_acl.status != -1) {
            wr_acl = session.put("sp/llc/acl", acl_payload, acl_len);
        }
        if (wr_acl.status == 0 || wr_acl.status == -1) {
            ESP_LOGI(LTPDU_TAG, "ACL write succeeded");
        } else {
            ESP_LOGW(LTPDU_TAG, "ACL write status: %d", wr_acl.status);
        }

        // Verify ACL readback
        auto rd_acl = session.get("lb/0/sp/llc/acl");
        if (rd_acl.status != 0) {
            rd_acl = session.get("sp/llc/acl");
        }
        if (rd_acl.status == 0 && rd_acl.value.size() == acl_len &&
            memcmp(rd_acl.value.data(), acl_payload, acl_len) == 0) {
            ESP_LOGI(LTPDU_TAG, "ACL verified!");
        } else if (rd_acl.status == 0) {
            ESP_LOGI(LTPDU_TAG, "ACL readback received (%d bytes)", rd_acl.value.size());
        }
    }

    // Clean up temporary pairing slot so it does not count towards the 5-slot ceiling
    session.unpair();
    ESP_LOGI(LTPDU_TAG, "Provision complete for %s", host.c_str());
    return true;
}

}  // namespace litewave
}  // namespace esphome
