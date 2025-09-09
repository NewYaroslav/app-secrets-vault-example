#include <iostream>
#include <fstream>
#include <variant>
#include <functional>
#include <vector>
#include <string>
#include <array>
#include <algorithm>
#include <chrono>

#include <aes_cpp/aes_utils.hpp>
#include <hmac_cpp/hmac_utils.hpp>
#include <hmac_cpp/encoding.hpp>
#include <hmac_cpp/secret_string.hpp>
#include <hmac_cpp/secure_buffer.hpp>
#include <obfy/obfy_str.hpp>
#include <obfy/obfy_bytes.hpp>

#include "pepper/pepper_provider.hpp"

#include "json.hpp"
#include "file_io.hpp"
using json = nlohmann::json;

enum class VaultError {
    ERR_FORMAT = 1,
    ERR_KDF_PARAM,
    ERR_GCM_TAG,
    ERR_RNG
};

template <typename T, typename E>
using expected = std::variant<T, E>;

static void log_error(VaultError e) {
    std::cerr << "ERR: " << static_cast<int>(e) << "\n";
}

struct VaultFile {
    uint32_t v = 1;
    uint32_t iters;
    hmac_cpp::secure_buffer<uint8_t, true> salt;
    hmac_cpp::secure_buffer<uint8_t, true> iv;
    hmac_cpp::secure_buffer<uint8_t, true> tag;
    hmac_cpp::secure_buffer<uint8_t, true> ct;
    std::string aad;
};

static std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}
static std::string to_string(const std::vector<uint8_t>& v) {
    return std::string(v.begin(), v.end());
}

static std::string b64enc(const hmac_cpp::secure_buffer<uint8_t, true>& v) {
    return hmac_cpp::base64_encode(v.data(), v.size());
}
static expected<hmac_cpp::secure_buffer<uint8_t, true>, VaultError>
b64dec(const std::string& s) {
    std::vector<uint8_t> tmp;
    if (!hmac_cpp::base64_decode(s, tmp)) return VaultError::ERR_FORMAT;
    return hmac_cpp::secure_buffer<uint8_t, true>(std::move(tmp));
}

static expected<std::reference_wrapper<const hmac_cpp::secure_buffer<uint8_t, true>>,
                VaultError>
app_pepper() {
    static hmac_cpp::secure_buffer<uint8_t, true> p;
    if (p.size() == 0) {
        pepper::Config cfg;
        auto kid_tmp = OBFY_STR_ONCE("pepper:v1");
        std::string kid(kid_tmp);
        cfg.key_id = kid;
        hmac_cpp::secure_zero(&kid[0], kid.size());
        auto s_tmp = OBFY_BYTES_ONCE("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10");
        std::vector<uint8_t> s(s_tmp.data(), s_tmp.data() + s_tmp.size());
        cfg.app_salt = s;
        hmac_cpp::secure_zero(s.data(), s.size());
        pepper::Provider prov(cfg);
        std::vector<uint8_t> tmp;
        if (!prov.ensure(tmp)) return VaultError::ERR_RNG;
        p = hmac_cpp::secure_buffer<uint8_t, true>(std::move(tmp));
    }
    return std::cref(p);
}

static std::string serialize_vault(const VaultFile& vf) {
    json j;
    j["v"] = vf.v;
    j["kdf"] = {
        {"name","PBKDF2-HMAC-SHA256"},
        {"iters", vf.iters},
        {"salt", b64enc(vf.salt)},
        {"dkLen", 32}
    };
    j["aead"] = {
        {"alg","AES-256-GCM"},
        {"iv",  b64enc(vf.iv)},
        {"tag", b64enc(vf.tag)}
    };
    j["ciphertext"] = b64enc(vf.ct);
    if (!vf.aad.empty()) j["aad"] = vf.aad;
    return j.dump();
}

static expected<VaultFile, VaultError> parse_vault(const std::string& s) {
    try {
        auto j = json::parse(s);
        VaultFile vf;
        vf.v = j.at("v").get<uint32_t>();
        if (vf.v != 1) return VaultError::ERR_FORMAT;
        auto jk = j.at("kdf");
        vf.iters = jk.at("iters").get<uint32_t>();
        if (vf.iters < 100000 || vf.iters > 1000000)
            return VaultError::ERR_KDF_PARAM;
        auto salt_res = b64dec(jk.at("salt").get<std::string>());
        if (std::holds_alternative<VaultError>(salt_res))
            return std::get<VaultError>(salt_res);
        vf.salt = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(salt_res));

        auto ja = j.at("aead");
        auto iv_res = b64dec(ja.at("iv").get<std::string>());
        if (std::holds_alternative<VaultError>(iv_res))
            return std::get<VaultError>(iv_res);
        vf.iv   = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(iv_res));
        auto tag_res = b64dec(ja.at("tag").get<std::string>());
        if (std::holds_alternative<VaultError>(tag_res))
            return std::get<VaultError>(tag_res);
        vf.tag  = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(tag_res));

        auto ct_res = b64dec(j.at("ciphertext").get<std::string>());
        if (std::holds_alternative<VaultError>(ct_res))
            return std::get<VaultError>(ct_res);
        vf.ct   = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(ct_res));
        vf.aad  = j.value("aad", "");
        return vf;
    } catch (...) {
        return VaultError::ERR_FORMAT;
    }
}

static expected<hmac_cpp::secure_buffer<uint8_t, true>, VaultError>
derive_key(const std::string& password,
           const hmac_cpp::secure_buffer<uint8_t, true>& salt,
           uint32_t iters) {
    std::string pw_copy(password);
    hmac_cpp::secure_buffer<uint8_t, true> pw(std::move(pw_copy));
    auto pep_res = app_pepper();
    if (std::holds_alternative<VaultError>(pep_res))
        return std::get<VaultError>(pep_res);
    const auto& p = std::get<std::reference_wrapper<const hmac_cpp::secure_buffer<uint8_t, true>>>(pep_res).get();
    auto vec = hmac_cpp::pbkdf2_with_pepper(pw.data(), pw.size(),
                                            salt.data(), salt.size(),
                                            p.data(), p.size(),
                                            iters, 32);
    return hmac_cpp::secure_buffer<uint8_t, true>(std::move(vec));
}

static expected<VaultFile, VaultError>
create_vault(const std::string& master_password,
             const std::string& email,
             const std::string& password,
             uint32_t iters = 300000,
             const std::string& aad = "app=demo;v=1") {
    VaultFile vf;
    vf.v = 1;
    vf.iters = iters;
    auto salt_vec = hmac_cpp::random_bytes(16);
    if (salt_vec.size() != 16) return VaultError::ERR_RNG;
    vf.salt = hmac_cpp::secure_buffer<uint8_t, true>(std::move(salt_vec));
    auto key_res = derive_key(master_password, vf.salt, iters);
    if (std::holds_alternative<VaultError>(key_res))
        return std::get<VaultError>(key_res);
    auto key = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(key_res));
    std::array<uint8_t,32> key_arr{};
    std::copy(key.begin(), key.begin()+key_arr.size(), key_arr.begin());

    json payload = { {"email", email}, {"password", password} };
    std::string payload_str = payload.dump();
    hmac_cpp::secure_buffer<uint8_t, true> plain(std::move(payload_str));

    std::vector<uint8_t> aad_bytes = to_bytes(aad);
    std::vector<uint8_t> plain_vec(plain.begin(), plain.end());
    auto enc = aes_cpp::utils::encrypt_gcm(plain_vec, key_arr, aad_bytes);
    hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
    hmac_cpp::secure_zero(plain_vec.data(), plain_vec.size());
    vf.iv = hmac_cpp::secure_buffer<uint8_t, true>(std::vector<uint8_t>(enc.iv.begin(), enc.iv.end()));
    vf.ct = hmac_cpp::secure_buffer<uint8_t, true>(std::move(enc.ciphertext));
    vf.tag = hmac_cpp::secure_buffer<uint8_t, true>(std::vector<uint8_t>(enc.tag.begin(), enc.tag.end()));
    vf.aad = aad;
    return vf;
}

static expected<json, VaultError>
open_vault(const std::string& master_password, const VaultFile& vf) {
    auto key_res = derive_key(master_password, vf.salt, vf.iters);
    if (std::holds_alternative<VaultError>(key_res))
        return std::get<VaultError>(key_res);
    auto key = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(key_res));
    std::array<uint8_t,32> key_arr{};
    std::copy(key.begin(), key.begin()+key_arr.size(), key_arr.begin());
    std::array<uint8_t,12> iv{};
    if (vf.iv.size()!=iv.size()) return VaultError::ERR_FORMAT;
    std::copy(vf.iv.begin(), vf.iv.begin()+iv.size(), iv.begin());
    std::array<uint8_t,16> tag{};
    if (vf.tag.size()!=tag.size()) return VaultError::ERR_GCM_TAG;
    std::copy(vf.tag.begin(), vf.tag.begin()+tag.size(), tag.begin());

    std::vector<uint8_t> aad_bytes = to_bytes(vf.aad);
    std::vector<uint8_t> ct_vec(vf.ct.begin(), vf.ct.end());
    aes_cpp::utils::GcmEncryptedData pkt{std::chrono::system_clock::now(), iv, ct_vec, tag};
    std::string plain;
    try {
        plain = aes_cpp::utils::decrypt_gcm_to_string(pkt, key_arr, aad_bytes);
    } catch (...) {
        hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
        hmac_cpp::secure_zero(ct_vec.data(), ct_vec.size());
        return VaultError::ERR_GCM_TAG;
    }
    hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
    hmac_cpp::secure_zero(ct_vec.data(), ct_vec.size());
    try {
        auto j = json::parse(plain);
        hmac_cpp::secure_zero(&plain[0], plain.size());
        return j;
    } catch (...) {
        hmac_cpp::secure_zero(&plain[0], plain.size());
        return VaultError::ERR_FORMAT;
    }
}

static std::string b64url_encode(const std::vector<uint8_t>& data) {
    auto s = hmac_cpp::base64_encode(data);
    std::replace(s.begin(), s.end(), '+', '-');
    std::replace(s.begin(), s.end(), '/', '_');
    while (!s.empty() && s.back() == '=') s.pop_back();
    return s;
}

static expected<hmac_cpp::secure_buffer<uint8_t, true>, VaultError>
b64url_decode(const std::string& s) {
    std::string t = s;
    std::replace(t.begin(), t.end(), '-', '+');
    std::replace(t.begin(), t.end(), '_', '/');
    while (t.size() % 4) t.push_back('=');
    std::vector<uint8_t> out;
    if (!hmac_cpp::base64_decode(t, out)) return VaultError::ERR_FORMAT;
    hmac_cpp::secure_zero(&t[0], t.size());
    return hmac_cpp::secure_buffer<uint8_t, true>(std::move(out));
}

static expected<std::string, VaultError>
create_token(const std::string& master,
             const std::string& email,
             const std::string& password) {
    auto vf_res = create_vault(master, email, password);
    if (std::holds_alternative<VaultError>(vf_res))
        return std::get<VaultError>(vf_res);
    auto vf = std::get<VaultFile>(std::move(vf_res));
    json header = {
        {"typ","JWR"},
        {"alg","AES-256-GCM"},
        {"kdf","PBKDF2-HMAC-SHA256"}
    };
    std::string head = header.dump();
    std::string body = serialize_vault(vf);
    std::string token = b64url_encode(to_bytes(head)) + "." +
                        b64url_encode(to_bytes(body));
    hmac_cpp::secure_zero(&body[0], body.size());
    return token;
}

static expected<json, VaultError>
open_token(const std::string& master, const std::string& token) {
    auto pos = token.find('.');
    if (pos == std::string::npos) return VaultError::ERR_FORMAT;
    std::string body_b64 = token.substr(pos+1);
    auto body_bytes_res = b64url_decode(body_b64);
    if (std::holds_alternative<VaultError>(body_bytes_res))
        return std::get<VaultError>(body_bytes_res);
    auto body_bytes = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(body_bytes_res));
    auto vf_res = parse_vault(std::string(body_bytes.begin(), body_bytes.end()));
    hmac_cpp::secure_zero(body_bytes.data(), body_bytes.size());
    if (std::holds_alternative<VaultError>(vf_res))
        return std::get<VaultError>(vf_res);
    auto payload = open_vault(master, std::get<VaultFile>(std::move(vf_res)));
    return payload;
}

int main() {
    const std::string master = "correct horse battery staple";
    const std::string email   = "user@example.com";
    const std::string pass    = "s3cr3t!";

    auto token_res = create_token(master, email, pass);
    if (std::holds_alternative<VaultError>(token_res)) {
        log_error(std::get<VaultError>(token_res));
        return 1;
    }
    auto token = std::get<std::string>(std::move(token_res));
    demo::atomic_write_file("vault.jwr", token);
    std::cout << "Token: " << token << "\n";

    std::string read_token;
    std::ifstream("vault.jwr") >> read_token;
    auto payload_res = open_token(master, read_token);
    if (std::holds_alternative<VaultError>(payload_res)) {
        log_error(std::get<VaultError>(payload_res));
        return 1;
    }
    auto payload = std::get<json>(std::move(payload_res));
    hmac_cpp::secret_string em(payload.at("email").get<std::string>());
    hmac_cpp::secret_string pw(payload.at("password").get<std::string>());
    std::cout << "Decrypted email: "    << em.reveal_copy() << "\n";
    std::cout << "Decrypted password: " << pw.reveal_copy() << "\n";
    em.clear();
    pw.clear();
    return 0;
}

