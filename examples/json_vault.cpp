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

static bool b64dec(const std::string& s,
                   hmac_cpp::secure_buffer<uint8_t, true>& out) {
    std::vector<uint8_t> tmp;
    if (!hmac_cpp::base64_decode(s, tmp)) return false;
    out = hmac_cpp::secure_buffer<uint8_t, true>(std::move(tmp));
    return true;
}

static std::string b64enc(const hmac_cpp::secure_buffer<uint8_t, true>& v) {
    return hmac_cpp::base64_encode(v.data(), v.size());
}

// runtime flags parsed from command line
static std::string g_pepper_mode = std::string(OBFY_STR("keystore"));
static bool g_deny_fallback = false;

static const char* kPepperKeyId = OBFY_STR("com.newyaroslav.app/v1/pepper");

static pepper::Provider& provider() {
    static std::unique_ptr<pepper::Provider> prov;
    if (!prov) {
        pepper::Config cfg;
        cfg.key_id = kPepperKeyId;
        auto s = OBFY_BYTES("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10");
        cfg.app_salt = std::vector<uint8_t>(s, s + 16);
        if (g_pepper_mode == std::string(OBFY_STR("derived"))) cfg.primary = pepper::StorageMode::MACHINE_BOUND;
        else if (g_pepper_mode == std::string(OBFY_STR("file"))) cfg.primary = pepper::StorageMode::ENCRYPTED_FILE;
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
    j["aead"] = {{"alg", "aes-256-gcm"}, {"iv", b64enc(vf.iv)}, {"aad", b64enc(vf.aad)}, {"ct", b64enc(vf.ct)}, {"tag", b64enc(vf.tag)}};
    return j.dump(2);
}

static bool parse_vault(const std::string& s, VaultFile& vf) {
    try {
        auto j = json::parse(s);
        vf.v = j.at("v").get<uint32_t>();
        if (vf.v != 1) return false;
        auto jk = j.at("kdf");
        if (jk.at("alg").get<std::string>() != "pbkdf2-hmac-sha256")
            return false;
        vf.iters = jk.at("iters").get<uint32_t>();
        if (vf.iters < 100000 || vf.iters > 1000000)
            return false;
        std::string salt_b64 = jk.at("salt").get<std::string>();
        if (!b64dec(salt_b64, vf.salt)) return false;
        hmac_cpp::secure_zero(&salt_b64[0], salt_b64.size());
        if (vf.salt.size() < 16) return false;
        auto ja = j.at("aead");
        if (ja.at("alg").get<std::string>() != "aes-256-gcm")
            return false;
        std::string iv_b64 = ja.at("iv").get<std::string>();
        if (!b64dec(iv_b64, vf.iv)) return false;
        hmac_cpp::secure_zero(&iv_b64[0], iv_b64.size());
        if (vf.iv.size() != 12) return false;
        std::string ct_b64 = ja.at("ct").get<std::string>();
        if (!b64dec(ct_b64, vf.ct)) return false;
        hmac_cpp::secure_zero(&ct_b64[0], ct_b64.size());
        std::string tag_b64 = ja.at("tag").get<std::string>();
        if (!b64dec(tag_b64, vf.tag)) return false;
        hmac_cpp::secure_zero(&tag_b64[0], tag_b64.size());
        if (vf.tag.size() != 16) return false;
        std::string aad_b64 = ja.value("aad", "");
        if (!b64dec(aad_b64, vf.aad)) return false;
        hmac_cpp::secure_zero(&aad_b64[0], aad_b64.size());
        return true;
    } catch (...) {
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
    std::vector<uint8_t> plain_vec(plain.begin(), plain.end());
    auto enc = aes_cpp::utils::encrypt_gcm(plain_vec, key_arr, aad_bytes);
    hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
    hmac_cpp::secure_zero(plain_vec.data(), plain_vec.size());
    hmac_cpp::secure_zero(aad_bytes.data(), aad_bytes.size());
    vf.iv = hmac_cpp::secure_buffer<uint8_t, true>(std::vector<uint8_t>(enc.iv.begin(), enc.iv.end()));
    vf.ct = hmac_cpp::secure_buffer<uint8_t, true>(std::move(enc.ciphertext));
    vf.tag = hmac_cpp::secure_buffer<uint8_t, true>(std::vector<uint8_t>(enc.tag.begin(), enc.tag.end()));
    vf.aad = aad_buf;
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
    std::copy(vf.iv.begin(), vf.iv.begin() + iv.size(), iv.begin());
    std::array<uint8_t,16> tag{};
    std::copy(vf.tag.begin(), vf.tag.begin() + tag.size(), tag.begin());

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
    hmac_cpp::secure_zero(aad_bytes.data(), aad_bytes.size());
    hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
    hmac_cpp::secure_zero(ct_vec.data(), ct_vec.size());
    try {
        auto j = json::parse(plain_vec.begin(), plain_vec.end());
        hmac_cpp::secure_zero(plain_vec.data(), plain_vec.size());
        return j;
    } catch (...) {
        hmac_cpp::secure_zero(plain_vec.data(), plain_vec.size());
        return VaultError::ERR_FORMAT;
    }
}

bool write_vault(const std::string& path,
                 const std::string& email,
                 const hmac_cpp::secret_string& passphrase,
                 Pepper& pepper) {
    (void)pepper;
    auto vf_res = create_vault(passphrase, email, passphrase, 300000);
    if (std::holds_alternative<VaultError>(vf_res)) {
        log_error(std::get<VaultError>(vf_res));
        return false;
    }
    auto vf = std::get<VaultFile>(std::move(vf_res));
    auto text = serialize_vault(vf);
    demo::atomic_write_file(path, text);
    hmac_cpp::secure_zero(&text[0], text.size());
    return true;
}

bool read_vault(const std::string& path,
                std::string& out_email,
                hmac_cpp::secret_string& out_password,
                const hmac_cpp::secret_string& passphrase,
                Pepper& pepper) {
    (void)pepper;
    std::ifstream ifs(path);
    std::stringstream buffer; buffer << ifs.rdbuf();
    std::string blob = buffer.str();
    VaultFile vf;
    bool ok = parse_vault(blob, vf);
    hmac_cpp::secure_zero(&blob[0], blob.size());
    if (!ok) {
        std::cerr << "ERR: parse vault\n";
        return false;
    }
    auto payload_res = open_vault(passphrase, vf);
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
    std::vector<std::string> pos;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind(std::string(OBFY_STR("--pepper=")), 0) == 0) g_pepper_mode = arg.substr(9);
        else if (arg == std::string(OBFY_STR("--deny-fallback"))) g_deny_fallback = true;
        else pos.push_back(arg);
    }
    if (pos.size() < 3) {
        std::cerr << "Usage: " << argv[0] << " [--pepper=MODE] [--deny-fallback] <path> <email> <passphrase>\n";
        return 1;
    }
    Pepper& prov = provider();
    hmac_cpp::secret_string passphrase(pos[2]);
    hmac_cpp::secure_zero(&pos[2][0], pos[2].size());
    if (!write_vault(pos[0], pos[1], passphrase, prov)) return 1;
    std::string out_email;
    hmac_cpp::secret_string out_password;
    if (!read_vault(pos[0], out_email, out_password, passphrase, prov)) return 1;
    std::cout << "Decrypted email: "    << out_email << "\n";
    auto pass_out = out_password.reveal_copy();
    std::cout << "Decrypted password: " << pass_out << "\n";
    hmac_cpp::secure_zero(&pass_out[0], pass_out.size());
    return 0;
}

