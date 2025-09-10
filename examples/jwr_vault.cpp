#include <iostream>
#include <fstream>
#include <variant>
#include <functional>
#include <vector>
#include <string>
#include <array>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cctype>

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
using Pepper = pepper::Provider;

static const auto aad = OBFY_BYTES_ONCE("app://secrets/blob/v1");

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
    hmac_cpp::secure_buffer<uint8_t, true> aad;
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
// Decode `s` from Base64 into `out`; reject non-Base64 input.
static bool b64dec(const std::string& s,
                   hmac_cpp::secure_buffer<uint8_t, true>& out) {
    std::vector<uint8_t> tmp;
    if (!hmac_cpp::base64_decode(s, tmp)) return false;
    out = hmac_cpp::secure_buffer<uint8_t, true>(std::move(tmp));
    return true;
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
    if (vf.aad.size()) j["aad"] = b64enc(vf.aad);
    return j.dump();
}

// Parse vault JSON and validate expected parameters.
// Only a boolean result is returned to keep failures generic.
static bool parse_vault(const std::string& s, VaultFile& vf) {
    try {
        auto j = json::parse(s);
        vf.v = j.at("v").get<uint32_t>();
        if (vf.v != 1) return false; // only version 1 supported
        auto jk = j.at("kdf");
        auto kdf_alg = jk.value("alg", jk.value("name", ""));
        std::transform(kdf_alg.begin(), kdf_alg.end(), kdf_alg.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        if (kdf_alg != "pbkdf2-hmac-sha256") return false; // unsupported KDF
        vf.iters = jk.at("iters").get<uint32_t>();
        if (vf.iters < 100000 || vf.iters > 1000000)
            return false; // enforce PBKDF2 iteration range
        std::string salt_b64 = jk.at("salt").get<std::string>();
        if (!b64dec(salt_b64, vf.salt)) return false;
        hmac_cpp::secure_zero(&salt_b64[0], salt_b64.size());
        if (vf.salt.size() < 16) return false; // min salt length

        auto ja = j.at("aead");
        auto aead_alg = ja.value("alg", "");
        std::transform(aead_alg.begin(), aead_alg.end(), aead_alg.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        if (aead_alg != "aes-256-gcm") return false; // unsupported AEAD
        std::string iv_b64 = ja.at("iv").get<std::string>();
        if (!b64dec(iv_b64, vf.iv)) return false;
        hmac_cpp::secure_zero(&iv_b64[0], iv_b64.size());
        if (vf.iv.size() != 12) return false; // GCM standard IV size
        std::string tag_b64 = ja.at("tag").get<std::string>();
        if (!b64dec(tag_b64, vf.tag)) return false;
        hmac_cpp::secure_zero(&tag_b64[0], tag_b64.size());
        if (vf.tag.size() != 16) return false; // GCM tag size

        std::string ct_b64 = j.at("ciphertext").get<std::string>();
        if (!b64dec(ct_b64, vf.ct)) return false;
        hmac_cpp::secure_zero(&ct_b64[0], ct_b64.size());
        std::string aad_b64 = j.value("aad", "");
        if (!b64dec(aad_b64, vf.aad)) return false;
        hmac_cpp::secure_zero(&aad_b64[0], aad_b64.size());
        return true;
    } catch (...) {
        // Swallow details; callers only see success/failure.
        return false;
    }
}

static expected<hmac_cpp::secure_buffer<uint8_t, true>, VaultError>
derive_key(const hmac_cpp::secret_string& password,
           const hmac_cpp::secure_buffer<uint8_t, true>& salt,
           uint32_t iters) {
    std::string pw_copy = password.reveal_copy();
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
create_vault(const hmac_cpp::secret_string& master_password,
             const std::string& email,
             const hmac_cpp::secret_string& password,
             uint32_t iters = 300000) {
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

    std::string pass_copy = password.reveal_copy();
    json payload = { {"email", email}, {"password", pass_copy} };
    hmac_cpp::secure_zero(&pass_copy[0], pass_copy.size());
    std::string payload_str = payload.dump();
    hmac_cpp::secure_buffer<uint8_t, true> plain(std::move(payload_str));

    hmac_cpp::secure_buffer<uint8_t, true> aad_buf(
        std::vector<uint8_t>(aad.data(), aad.data() + aad.size()));
    std::vector<uint8_t> aad_bytes(aad_buf.begin(), aad_buf.end());
    vf.aad = aad_buf;
    std::vector<uint8_t> plain_vec(plain.begin(), plain.end());
    auto enc = aes_cpp::utils::encrypt_gcm(plain_vec, key_arr, aad_bytes);
    hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
    hmac_cpp::secure_zero(plain_vec.data(), plain_vec.size());
    hmac_cpp::secure_zero(aad_bytes.data(), aad_bytes.size());
    vf.iv = hmac_cpp::secure_buffer<uint8_t, true>(std::vector<uint8_t>(enc.iv.begin(), enc.iv.end()));
    vf.ct = hmac_cpp::secure_buffer<uint8_t, true>(std::move(enc.ciphertext));
    vf.tag = hmac_cpp::secure_buffer<uint8_t, true>(std::vector<uint8_t>(enc.tag.begin(), enc.tag.end()));
    return vf;
}

static expected<json, VaultError>
open_vault(const hmac_cpp::secret_string& master_password, const VaultFile& vf) {
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

    std::vector<uint8_t> aad_bytes(vf.aad.begin(), vf.aad.end());
    std::vector<uint8_t> ct_vec(vf.ct.begin(), vf.ct.end());
    aes_cpp::utils::GcmEncryptedData pkt{std::chrono::system_clock::now(), iv, ct_vec, tag};
    std::vector<uint8_t> plain_vec;
    try {
        plain_vec = aes_cpp::utils::decrypt_gcm(pkt, key_arr, aad_bytes);
    } catch (...) {
        hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
        hmac_cpp::secure_zero(ct_vec.data(), ct_vec.size());
        hmac_cpp::secure_zero(aad_bytes.data(), aad_bytes.size());
        return VaultError::ERR_GCM_TAG;
    }
    hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
    hmac_cpp::secure_zero(ct_vec.data(), ct_vec.size());
    hmac_cpp::secure_zero(aad_bytes.data(), aad_bytes.size());
    try {
        auto j = json::parse(plain_vec.begin(), plain_vec.end());
        hmac_cpp::secure_zero(plain_vec.data(), plain_vec.size());
        return j;
    } catch (...) {
        hmac_cpp::secure_zero(plain_vec.data(), plain_vec.size());
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
create_token(const hmac_cpp::secret_string& master,
             const std::string& email,
             const hmac_cpp::secret_string& password) {
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
open_token(const hmac_cpp::secret_string& master, const std::string& token) {
    auto pos = token.find('.');
    if (pos == std::string::npos) return VaultError::ERR_FORMAT;
    std::string body_b64 = token.substr(pos+1);
    auto body_bytes_res = b64url_decode(body_b64);
    hmac_cpp::secure_zero(&body_b64[0], body_b64.size());
    if (std::holds_alternative<VaultError>(body_bytes_res))
        return std::get<VaultError>(body_bytes_res);
    auto body_bytes = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(body_bytes_res));
    std::string body_str(body_bytes.begin(), body_bytes.end());
    VaultFile vf;
    bool ok = parse_vault(body_str, vf);
    hmac_cpp::secure_zero(&body_str[0], body_str.size());
    hmac_cpp::secure_zero(body_bytes.data(), body_bytes.size());
    if (!ok) return VaultError::ERR_FORMAT;
    auto payload = open_vault(master, vf);
    return payload;
}

bool write_vault(const std::string& path,
                 const std::string& email,
                 const hmac_cpp::secret_string& passphrase,
                 Pepper& pepper) {
    (void)pepper;
    auto token_res = create_token(passphrase, email, passphrase);
    if (std::holds_alternative<VaultError>(token_res)) {
        log_error(std::get<VaultError>(token_res));
        return false;
    }
    auto token = std::get<std::string>(std::move(token_res));
    demo::atomic_write_file(path, token);
    hmac_cpp::secure_zero(&token[0], token.size());
    return true;
}

bool read_vault(const std::string& path,
                std::string& out_email,
                hmac_cpp::secret_string& out_password,
                const hmac_cpp::secret_string& passphrase,
                Pepper& pepper) {
    (void)pepper;
    std::string read_token;
    std::ifstream(path) >> read_token;
    auto payload_res = open_token(passphrase, read_token);
    if (std::holds_alternative<VaultError>(payload_res)) {
        log_error(std::get<VaultError>(payload_res));
        return false;
    }
    auto payload = std::get<json>(std::move(payload_res));
    out_email = payload.at("email").get<std::string>();
    std::string pwd_tmp = payload.at("password").get<std::string>();
    out_password = hmac_cpp::secret_string(pwd_tmp);
    hmac_cpp::secure_zero(&pwd_tmp[0], pwd_tmp.size());
    return true;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <path> <email> <passphrase>\n";
        return 1;
    }
    pepper::Config cfg;
    auto kid_tmp = OBFY_STR_ONCE("pepper:v1");
    cfg.key_id = std::string(kid_tmp);
    auto s_tmp = OBFY_BYTES_ONCE("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10");
    cfg.app_salt = std::vector<uint8_t>(s_tmp.data(), s_tmp.data()+s_tmp.size());
    Pepper prov(cfg);
    hmac_cpp::secret_string passphrase(argv[3]);
    hmac_cpp::secure_zero(argv[3], std::strlen(argv[3]));
    if (!write_vault(argv[1], argv[2], passphrase, prov)) return 1;
    std::string out_email;
    hmac_cpp::secret_string out_password;
    if (!read_vault(argv[1], out_email, out_password, passphrase, prov)) return 1;
    std::cout << "Decrypted email: "    << out_email << "\n";
    auto pass_out = out_password.reveal_copy();
    std::cout << "Decrypted password: " << pass_out << "\n";
    hmac_cpp::secure_zero(&pass_out[0], pass_out.size());
    return 0;
}

