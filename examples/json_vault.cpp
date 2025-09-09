#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <string>
#include <array>
#include <chrono>

#include <aes_cpp/aes_utils.hpp>
#include <hmac_cpp/hmac_utils.hpp>
#include <hmac_cpp/encoding.hpp>
#include <hmac_cpp/secret_string.hpp>
#include <obfy/obfy_str.hpp>
#include <obfy/obfy_bytes.hpp>

#include "pepper/pepper_provider.hpp"

#include "json.hpp"
using json = nlohmann::json;

struct VaultFile {
    uint32_t v = 1;
    uint32_t iters;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
    std::vector<uint8_t> ct;
    std::string aad;
};

static std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}
static std::string to_string(const std::vector<uint8_t>& v) {
    return std::string(v.begin(), v.end());
}

static std::string b64enc(const std::vector<uint8_t>& v) {
    return hmac_cpp::base64_encode(v);
}
static std::vector<uint8_t> b64dec(const std::string& s) {
    std::vector<uint8_t> out;
    if (!hmac_cpp::base64_decode(s, out)) throw std::runtime_error("b64");
    return out;
}

static const std::vector<uint8_t>& app_pepper() {
    static std::vector<uint8_t> p;
    if (p.empty()) {
        pepper::Config cfg;
        cfg.key_id = OBFY_STR("pepper:v1");
        auto s = OBFY_BYTES("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10");
        cfg.app_salt = std::vector<uint8_t>(s, s + 16);
        pepper::Provider prov(cfg);
        if (!prov.ensure(p)) throw std::runtime_error("pepper");
    }
    return p;
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
    return j.dump(2);
}

static VaultFile parse_vault(const std::string& s) {
    auto j = json::parse(s);
    VaultFile vf;
    vf.v = j.at("v").get<uint32_t>();
    auto jk = j.at("kdf");
    vf.iters = jk.at("iters").get<uint32_t>();
    vf.salt  = b64dec(jk.at("salt").get<std::string>());

    auto ja = j.at("aead");
    vf.iv   = b64dec(ja.at("iv").get<std::string>());
    vf.tag  = b64dec(ja.at("tag").get<std::string>());

    vf.ct   = b64dec(j.at("ciphertext").get<std::string>());
    vf.aad  = j.value("aad", "");
    return vf;
}

static std::array<uint8_t,32> derive_key(const std::string& password,
                                         const std::vector<uint8_t>& salt,
                                         uint32_t iters) {
    auto pw = to_bytes(password);
    const auto& pep = app_pepper();
    auto vec = hmac_cpp::pbkdf2_with_pepper(pw, salt, pep, iters, 32);
    std::array<uint8_t,32> key{};
    std::copy(vec.begin(), vec.end(), key.begin());
    return key;
}

static VaultFile create_vault(const std::string& master_password,
                              const std::string& email,
                              const std::string& password,
                              uint32_t iters = 300000,
                              const std::string& aad = "app=demo;v=1")
{
    VaultFile vf;
    vf.v = 1;
    vf.iters = iters;
    vf.salt = hmac_cpp::random_bytes(16);
    auto key = derive_key(master_password, vf.salt, iters);

    json payload = { {"email", email}, {"password", password} };
    auto plain = to_bytes(payload.dump());

    std::vector<uint8_t> aad_bytes = to_bytes(aad);
    auto enc = aes_cpp::utils::encrypt_gcm(plain, key, aad_bytes);
    vf.iv.assign(enc.iv.begin(), enc.iv.end());
    vf.ct  = std::move(enc.ciphertext);
    vf.tag.assign(enc.tag.begin(), enc.tag.end());
    vf.aad = aad;
    return vf;
}

static json open_vault(const std::string& master_password, const VaultFile& vf) {
    auto key = derive_key(master_password, vf.salt, vf.iters);
    std::array<uint8_t,12> iv{};
    if (vf.iv.size()!=iv.size()) throw std::runtime_error("bad iv size");
    std::copy(vf.iv.begin(), vf.iv.end(), iv.begin());
    std::array<uint8_t,16> tag{};
    if (vf.tag.size()!=tag.size()) throw std::runtime_error("bad tag size");
    std::copy(vf.tag.begin(), vf.tag.end(), tag.begin());

    std::vector<uint8_t> aad_bytes = to_bytes(vf.aad);
    aes_cpp::utils::GcmEncryptedData pkt{std::chrono::system_clock::now(), iv, vf.ct, tag};
    auto plain = aes_cpp::utils::decrypt_gcm_to_string(pkt, key, aad_bytes);
    return json::parse(plain);
}

int main() {
    try {
        const std::string master = "correct horse battery staple";
        const std::string email   = "user@example.com";
        const std::string pass    = "s3cr3t!";

        auto vf = create_vault(master, email, pass, 300000, "app=demo;v=1");
        auto text = serialize_vault(vf);
        std::ofstream("vault.json") << text;
        std::cout << "Saved JSON:\n" << text << "\n";

        std::ifstream ifs("vault.json");
        std::stringstream buffer; buffer << ifs.rdbuf();
        VaultFile vf2 = parse_vault(buffer.str());
        auto payload  = open_vault(master, vf2);
        hmac_cpp::secret_string em(payload.at("email").get<std::string>());
        hmac_cpp::secret_string pw(payload.at("password").get<std::string>());
        std::cout << "Decrypted email: "    << em.reveal_copy() << "\n";
        std::cout << "Decrypted password: " << pw.reveal_copy() << "\n";
        em.clear();
        pw.clear();
    } catch (const std::exception& e) {
        std::cerr << "ERR: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

