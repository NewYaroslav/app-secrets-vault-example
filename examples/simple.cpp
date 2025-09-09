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
#include <hmac_cpp/secure_buffer.hpp>
#include <obfy/obfy_str.hpp>
#include <obfy/obfy_bytes.hpp>

#include "pepper/pepper_provider.hpp"
#include "file_io.hpp"

static std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

static std::string b64enc(const hmac_cpp::secure_buffer<uint8_t, true>& v) {
    return hmac_cpp::base64_encode(v.data(), v.size());
}
static hmac_cpp::secure_buffer<uint8_t, true> b64dec(const std::string& s) {
    std::vector<uint8_t> out;
    if (!hmac_cpp::base64_decode(s, out)) throw std::runtime_error("b64");
    return hmac_cpp::secure_buffer<uint8_t, true>(std::move(out));
}

static const hmac_cpp::secure_buffer<uint8_t, true>& app_pepper() {
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
        if (!prov.ensure(tmp)) throw std::runtime_error("pepper");
        p = hmac_cpp::secure_buffer<uint8_t, true>(std::move(tmp));
    }
    return p;
}

static std::array<uint8_t,32> derive_key(const hmac_cpp::secret_string& password,
                                         const hmac_cpp::secure_buffer<uint8_t, true>& salt,
                                         uint32_t iters) {
    std::string pw_copy = password.reveal_copy();
    hmac_cpp::secure_buffer<uint8_t, true> pw(std::move(pw_copy));
    auto key_vec = hmac_cpp::pbkdf2_with_pepper(pw.data(), pw.size(),
                                                salt.data(), salt.size(),
                                                app_pepper().data(), app_pepper().size(),
                                                iters, 32);
    std::array<uint8_t,32> key{};
    std::copy(key_vec.begin(), key_vec.end(), key.begin());
    hmac_cpp::secure_zero(key_vec.data(), key_vec.size());
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
        hmac_cpp::secret_string master("correct horse battery staple");
        const std::string email  = "user@example.com";
        const std::string pass   = "s3cr3t!";
        const uint32_t iters = 300000;
        auto aad_tmp = OBFY_BYTES_ONCE("demo1");
        hmac_cpp::secure_buffer<uint8_t, true> aad_buf(
            std::vector<uint8_t>(aad_tmp.data(), aad_tmp.data() + aad_tmp.size()));

        std::string payload = email + ":" + pass;
        std::vector<uint8_t> payload_vec(payload.begin(), payload.end());
        hmac_cpp::secure_buffer<uint8_t, true> plain_buf(std::move(payload_vec));
        hmac_cpp::secure_zero(&payload[0], payload.size());
        payload.clear();

        auto salt = hmac_cpp::secure_buffer<uint8_t, true>(hmac_cpp::random_bytes(16));
        auto key  = derive_key(master, salt, iters);

        std::vector<uint8_t> aad_bytes(aad_buf.begin(), aad_buf.end());
        std::vector<uint8_t> plain_vec(plain_buf.begin(), plain_buf.end());
        auto enc = aes_cpp::utils::encrypt_gcm(plain_vec, key, aad_bytes);
        hmac_cpp::secure_zero(key.data(), key.size());
        hmac_cpp::secure_zero(plain_vec.data(), plain_vec.size());

        auto iv  = hmac_cpp::secure_buffer<uint8_t, true>(std::vector<uint8_t>(enc.iv.begin(), enc.iv.end()));
        auto tag = hmac_cpp::secure_buffer<uint8_t, true>(std::vector<uint8_t>(enc.tag.begin(), enc.tag.end()));
        auto ct  = hmac_cpp::secure_buffer<uint8_t, true>(std::move(enc.ciphertext));

        std::string serialized =
            std::to_string(iters) + ":" +
            b64enc(salt) + ":" +
            b64enc(iv) + ":" +
            b64enc(tag) + ":" +
            b64enc(ct);

        demo::atomic_write_file("vault_simple.dat", serialized);

        std::string in;
        std::ifstream("vault_simple.dat") >> in;
        auto parts = split(in, ':');
        hmac_cpp::secure_zero(&in[0], in.size());
        if (parts.size() != 5) {
            throw std::runtime_error("bad vault format");
        }

        uint32_t iters2 = static_cast<uint32_t>(std::stoul(parts[0]));
        auto salt2 = b64dec(parts[1]);
        auto iv2   = b64dec(parts[2]);
        auto tag2  = b64dec(parts[3]);
        auto ct2   = b64dec(parts[4]);

        auto key2 = derive_key(master, salt2, iters2);

        aes_cpp::utils::GcmEncryptedData packet;
        std::copy(iv2.begin(), iv2.begin()+packet.iv.size(), packet.iv.begin());
        std::vector<uint8_t> ct_vec(ct2.begin(), ct2.end());
        packet.ciphertext = ct_vec;
        std::copy(tag2.begin(), tag2.begin()+packet.tag.size(), packet.tag.begin());

        std::string plain = aes_cpp::utils::decrypt_gcm_to_string(packet, key2, aad_bytes);
        hmac_cpp::secure_zero(key2.data(), key2.size());
        hmac_cpp::secure_zero(ct_vec.data(), ct_vec.size());

        hmac_cpp::secret_string secret(plain);
        hmac_cpp::secure_zero(&plain[0], plain.size());
        std::cout << "Decoded: " << secret.reveal_copy() << std::endl;
        secret.clear();
        hmac_cpp::secure_zero(aad_bytes.data(), aad_bytes.size());
    } catch (const std::exception& e) {
        std::cerr << "ERR: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

