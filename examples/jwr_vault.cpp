#include <iostream>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <string>
#include <array>
#include <algorithm>
#include <chrono>

#include <aes_cpp/aes_utils.hpp>
#include <hmac_cpp/hmac_utils.hpp>
#include <hmac_cpp/encoding.hpp>
#include <hmac_cpp/secret_string.hpp>
#include <obfy/obfy_str.hpp>

#include "json.hpp"
using json = nlohmann::json;

using namespace aes_cpp;
using namespace hmac_cpp;

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

static std::string pepper() {
    return std::string(OBFY_STR("demo_pepper"));
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
    auto pep = to_bytes(pepper());
    auto vec = pbkdf2_with_pepper(pw, salt, pep, iters, 32);
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
    vf.salt = random_bytes(16);
    auto key = derive_key(master_password, vf.salt, iters);

    json payload = { {"email", email}, {"password", password} };
    auto plain = to_bytes(payload.dump());

    std::vector<uint8_t> aad_bytes = to_bytes(aad);
    auto enc = utils::encrypt_gcm(plain, key, aad_bytes);
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
    utils::GcmEncryptedData pkt{std::chrono::system_clock::now(), iv, vf.ct, tag};
    auto plain = utils::decrypt_gcm_to_string(pkt, key, aad_bytes);
    return json::parse(plain);
}

static std::string b64url_encode(const std::vector<uint8_t>& data) {
    auto s = hmac_cpp::base64_encode(data);
    std::replace(s.begin(), s.end(), '+', '-');
    std::replace(s.begin(), s.end(), '/', '_');
    while (!s.empty() && s.back() == '=') s.pop_back();
    return s;
}

static std::vector<uint8_t> b64url_decode(const std::string& s) {
    std::string t = s;
    std::replace(t.begin(), t.end(), '-', '+');
    std::replace(t.begin(), t.end(), '_', '/');
    while (t.size() % 4) t.push_back('=');
    std::vector<uint8_t> out;
    if (!hmac_cpp::base64_decode(t, out)) throw std::runtime_error("b64");
    return out;
}

static std::string create_token(const std::string& master,
                                const std::string& email,
                                const std::string& password) {
    auto vf = create_vault(master, email, password);
    json header = {
        {"typ","JWR"},
        {"alg","AES-256-GCM"},
        {"kdf","PBKDF2-HMAC-SHA256"}
    };
    std::string head = header.dump();
    std::string body = serialize_vault(vf);
    std::string token = b64url_encode(to_bytes(head)) + "." +
                        b64url_encode(to_bytes(body));
    return token;
}

static json open_token(const std::string& master, const std::string& token) {
    auto pos = token.find('.');
    if (pos == std::string::npos) throw std::runtime_error("bad token");
    std::string body_b64 = token.substr(pos+1);
    auto body_bytes = b64url_decode(body_b64);
    VaultFile vf = parse_vault(std::string(body_bytes.begin(), body_bytes.end()));
    return open_vault(master, vf);
}

int main() {
    try {
        const std::string master = "correct horse battery staple";
        const std::string email   = "user@example.com";
        const std::string pass    = "s3cr3t!";

        auto token = create_token(master, email, pass);
        std::ofstream("vault.jwr") << token;
        std::cout << "Token: " << token << "\n";

        std::string read_token;
        std::ifstream("vault.jwr") >> read_token;
        auto payload = open_token(master, read_token);
        secret_string em(payload.at("email").get<std::string>());
        secret_string pw(payload.at("password").get<std::string>());
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

