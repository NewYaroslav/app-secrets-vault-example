#include <iostream>
#include <fstream>
#include <sstream>
#include <variant>
#include <functional>
#include <vector>
#include <string>
#include <array>
#include <chrono>
#include <memory>

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

static expected<hmac_cpp::secure_buffer<uint8_t, true>, VaultError>
b64dec(const std::string& s) {
    std::vector<uint8_t> tmp;
    if (!hmac_cpp::base64_decode(s, tmp)) return VaultError::ERR_FORMAT;
    return hmac_cpp::secure_buffer<uint8_t, true>(std::move(tmp));
}

static std::string b64enc(const hmac_cpp::secure_buffer<uint8_t, true>& v) {
    return hmac_cpp::base64_encode(v.data(), v.size());
}

// runtime flags parsed from command line
static std::string g_pepper_mode = "keystore";
static bool g_deny_fallback = false;

static const char* kPepperKeyId = OBFY_STR("com.newyaroslav.app/v1/pepper");

static pepper::Provider& provider() {
    static std::unique_ptr<pepper::Provider> prov;
    if (!prov) {
        pepper::Config cfg;
        cfg.key_id = kPepperKeyId;
        auto s = OBFY_BYTES("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10");
        cfg.app_salt = std::vector<uint8_t>(s, s + 16);
        if (g_pepper_mode == "derived") cfg.primary = pepper::StorageMode::MACHINE_BOUND;
        else if (g_pepper_mode == "file") cfg.primary = pepper::StorageMode::ENCRYPTED_FILE;
        else cfg.primary = pepper::StorageMode::OS_KEYCHAIN;
        if (g_deny_fallback) cfg.fallbacks.clear();
        prov = std::make_unique<pepper::Provider>(cfg);
    }
    return *prov;
}

static expected<std::reference_wrapper<const hmac_cpp::secure_buffer<uint8_t, true>>,
                VaultError>
app_pepper() {
    static hmac_cpp::secure_buffer<uint8_t, true> p;
    if (p.size()==0) {
        std::vector<uint8_t> tmp;
        if (!provider().ensure(tmp)) return VaultError::ERR_RNG;
        p = hmac_cpp::secure_buffer<uint8_t, true>(std::move(tmp));
    }
    return std::cref(p);
}

static std::string serialize_vault(const VaultFile& vf) {
    json j;
    j["v"] = vf.v;
    j["kdf"] = {{"alg", "pbkdf2-hmac-sha256"}, {"iters", vf.iters}, {"salt", b64enc(vf.salt)}};
    j["aead"] = {{"alg", "aes-256-gcm"}, {"iv", b64enc(vf.iv)}, {"aad", vf.aad}, {"ct", b64enc(vf.ct)}, {"tag", b64enc(vf.tag)}};
    return j.dump(2);
}

static expected<VaultFile, VaultError> parse_vault(const std::string& s) {
    try {
        auto j = json::parse(s);
        VaultFile vf;
        vf.v = j.at("v").get<uint32_t>();
        if (vf.v != 1) return VaultError::ERR_FORMAT;
        auto jk = j.at("kdf");
        if (jk.at("alg").get<std::string>() != "pbkdf2-hmac-sha256")
            return VaultError::ERR_KDF_PARAM;
        vf.iters = jk.at("iters").get<uint32_t>();
        if (vf.iters < 100000 || vf.iters > 1000000)
            return VaultError::ERR_KDF_PARAM;
        auto salt_res = b64dec(jk.at("salt").get<std::string>());
        if (std::holds_alternative<VaultError>(salt_res))
            return std::get<VaultError>(salt_res);
        vf.salt = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(salt_res));
        if (vf.salt.size() < 16 || vf.salt.size() > 32)
            return VaultError::ERR_KDF_PARAM;
        auto ja = j.at("aead");
        if (ja.at("alg").get<std::string>() != "aes-256-gcm")
            return VaultError::ERR_FORMAT;
        auto iv_res = b64dec(ja.at("iv").get<std::string>());
        if (std::holds_alternative<VaultError>(iv_res))
            return std::get<VaultError>(iv_res);
        vf.iv = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(iv_res));
        if (vf.iv.size() != 12) return VaultError::ERR_FORMAT;
        auto ct_res = b64dec(ja.at("ct").get<std::string>());
        if (std::holds_alternative<VaultError>(ct_res))
            return std::get<VaultError>(ct_res);
        vf.ct = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(ct_res));
        auto tag_res = b64dec(ja.at("tag").get<std::string>());
        if (std::holds_alternative<VaultError>(tag_res))
            return std::get<VaultError>(tag_res);
        vf.tag = std::get<hmac_cpp::secure_buffer<uint8_t, true>>(std::move(tag_res));
        if (vf.tag.size() != 16) return VaultError::ERR_GCM_TAG;
        vf.aad  = ja.value("aad", "");
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

    std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());
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
    std::copy(vf.iv.begin(), vf.iv.begin() + iv.size(), iv.begin());
    std::array<uint8_t,16> tag{};
    std::copy(vf.tag.begin(), vf.tag.begin() + tag.size(), tag.begin());

    std::vector<uint8_t> aad_bytes(vf.aad.begin(), vf.aad.end());
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

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--pepper=", 0) == 0) g_pepper_mode = arg.substr(9);
        else if (arg == "--deny-fallback") g_deny_fallback = true;
    }

    const std::string master = "correct horse battery staple";
    const std::string email   = "user@example.com";
    const std::string pass    = "s3cr3t!";

    auto aad_tmp = OBFY_BYTES_ONCE("app://secrets/blob/v1");
    std::string aad(reinterpret_cast<const char*>(aad_tmp.data()), aad_tmp.size());
    auto vf_res = create_vault(master, email, pass, 300000, aad);
    if (std::holds_alternative<VaultError>(vf_res)) {
        log_error(std::get<VaultError>(vf_res));
        return 1;
    }
    auto vf = std::get<VaultFile>(std::move(vf_res));
    auto text = serialize_vault(vf);
    demo::atomic_write_file("vault.json", text);
    std::cout << "Saved JSON:\n" << text << "\n";

    std::ifstream ifs("vault.json");
    std::stringstream buffer; buffer << ifs.rdbuf();
    std::string blob = buffer.str();
    auto pv = parse_vault(blob);
    hmac_cpp::secure_zero(&blob[0], blob.size());
    blob.clear();
    if (std::holds_alternative<VaultError>(pv)) {
        log_error(std::get<VaultError>(pv));
        return 1;
    }
    VaultFile vf2 = std::get<VaultFile>(std::move(pv));
    auto payload_res = open_vault(master, vf2);
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

