#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <array>
#include <algorithm>
#include <stdexcept>

#include <aes_cpp/aes_utils.hpp>
#include <hmac_cpp/hmac_utils.hpp>
#include <hmac_cpp/encoding.hpp>
#include <hmac_cpp/secret_string.hpp>
#include <obfy/obfy_str.hpp>

using namespace aes_cpp;
using namespace hmac_cpp;

static std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
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

static std::array<uint8_t,32> derive_key(const std::string& password,
                                         const std::vector<uint8_t>& salt,
                                         uint32_t iters) {
    auto pw = to_bytes(password);
    auto pep = to_bytes(pepper());
    auto key_vec = pbkdf2_with_pepper(pw, salt, pep, iters, 32);
    std::array<uint8_t,32> key{};
    std::copy(key_vec.begin(), key_vec.end(), key.begin());
    return key;
}

static std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        parts.push_back(item);
    }
    return parts;
}

int main() {
    try {
        const std::string master = "correct horse battery staple";
        const std::string email  = "user@example.com";
        const std::string pass   = "s3cr3t!";
        const uint32_t iters = 300000;
        const std::string aad = "demo1";

        std::string payload = email + ":" + pass;

        auto salt = random_bytes(16);
        auto key  = derive_key(master, salt, iters);

        std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());
        auto enc = utils::encrypt_gcm(payload, key, aad_bytes);

        std::string serialized =
            std::to_string(iters) + ":" +
            b64enc(salt) + ":" +
            b64enc(std::vector<uint8_t>(enc.iv.begin(), enc.iv.end())) + ":" +
            b64enc(std::vector<uint8_t>(enc.tag.begin(), enc.tag.end())) + ":" +
            b64enc(enc.ciphertext);

        std::ofstream("vault_simple.dat") << serialized;

        std::string in;
        std::ifstream("vault_simple.dat") >> in;
        auto parts = split(in, ':');
        if (parts.size() != 5) {
            throw std::runtime_error("bad vault format");
        }

        uint32_t iters2 = static_cast<uint32_t>(std::stoul(parts[0]));
        auto salt2 = b64dec(parts[1]);
        auto iv2   = b64dec(parts[2]);
        auto tag2  = b64dec(parts[3]);
        auto ct2   = b64dec(parts[4]);

        auto key2 = derive_key(master, salt2, iters2);

        utils::GcmEncryptedData packet;
        std::copy(iv2.begin(), iv2.end(), packet.iv.begin());
        packet.ciphertext = ct2;
        std::copy(tag2.begin(), tag2.end(), packet.tag.begin());

        std::string plain = utils::decrypt_gcm_to_string(packet, key2, aad_bytes);

        secret_string secret(plain);
        std::cout << "Decoded: " << secret.reveal_copy() << std::endl;
        secret.clear();
    } catch (const std::exception& e) {
        std::cerr << "ERR: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

