#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <array>
#include <algorithm>
#include <stdexcept>
#include <cstring>

#include <aes_cpp/aes_utils.hpp>
#include <hmac_cpp/hmac_utils.hpp>
#include <hmac_cpp/encoding.hpp>
#include <hmac_cpp/secret_string.hpp>
#include <hmac_cpp/secure_buffer.hpp>
#include <obfy/obfy_str.hpp>
#include <obfy/obfy_bytes.hpp>

#include "pepper/pepper_provider.hpp"
#include "file_io.hpp"

using Pepper = pepper::Provider;

static const auto aad = OBFY_BYTES_ONCE("app://secrets/blob/v1");

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

bool write_vault(const std::string& path,
                 const std::string& email,
                 const hmac_cpp::secret_string& passphrase,
                 Pepper& pepper) {
    (void)pepper;
    try {
        const hmac_cpp::secret_string& master = passphrase;
        const uint32_t iters = 300000;
        std::vector<uint8_t> aad_bytes(aad.data(), aad.data() + aad.size());

        std::string pass_copy = passphrase.reveal_copy();
        std::string payload = email + ":" + pass_copy;
        hmac_cpp::secure_zero(&pass_copy[0], pass_copy.size());
        std::vector<uint8_t> payload_vec(payload.begin(), payload.end());
        hmac_cpp::secure_buffer<uint8_t, true> plain_buf(std::move(payload_vec));
        hmac_cpp::secure_zero(&payload[0], payload.size());

        auto salt_vec = hmac_cpp::random_bytes(16);
        if (salt_vec.size() != 16) {
            hmac_cpp::secure_zero(salt_vec.data(), salt_vec.size());
            return false;
        }
        auto salt = hmac_cpp::secure_buffer<uint8_t, true>(std::move(salt_vec));
        auto key  = derive_key(master, salt, iters);

        std::vector<uint8_t> plain_vec(plain_buf.begin(), plain_buf.end());
        auto enc = aes_cpp::utils::encrypt_gcm(plain_vec, key, aad_bytes);
        hmac_cpp::secure_zero(key.data(), key.size());
        hmac_cpp::secure_zero(plain_vec.data(), plain_vec.size());
        hmac_cpp::secure_zero(aad_bytes.data(), aad_bytes.size());

        auto iv  = hmac_cpp::secure_buffer<uint8_t, true>(std::vector<uint8_t>(enc.iv.begin(), enc.iv.end()));
        auto tag = hmac_cpp::secure_buffer<uint8_t, true>(std::vector<uint8_t>(enc.tag.begin(), enc.tag.end()));
        auto ct  = hmac_cpp::secure_buffer<uint8_t, true>(std::move(enc.ciphertext));

        std::string serialized =
            std::to_string(iters) + ":" +
            b64enc(salt) + ":" +
            b64enc(iv) + ":" +
            b64enc(tag) + ":" +
            b64enc(ct);

        demo::atomic_write_file(path, serialized);
        hmac_cpp::secure_zero(&serialized[0], serialized.size());
        return true;
    } catch (...) {
        return false;
    }
}

bool read_vault(const std::string& path,
                std::string& out_email,
                hmac_cpp::secret_string& out_password,
                const hmac_cpp::secret_string& passphrase,
                Pepper& pepper) {
    (void)pepper;
    try {
        const hmac_cpp::secret_string& master = passphrase;
        std::string in;
        std::ifstream(path) >> in;
        auto parts = split(in, ':');
        hmac_cpp::secure_zero(&in[0], in.size());
        if (parts.size() != 5) return false;

        uint32_t iters = static_cast<uint32_t>(std::stoul(parts[0]));
        auto salt = b64dec(parts[1]);
        hmac_cpp::secure_zero(&parts[1][0], parts[1].size());
        auto iv   = b64dec(parts[2]);
        hmac_cpp::secure_zero(&parts[2][0], parts[2].size());
        auto tag  = b64dec(parts[3]);
        hmac_cpp::secure_zero(&parts[3][0], parts[3].size());
        auto ct   = b64dec(parts[4]);
        hmac_cpp::secure_zero(&parts[4][0], parts[4].size());

        auto key = derive_key(master, salt, iters);

        std::vector<uint8_t> aad_bytes(aad.data(), aad.data()+aad.size());
        aes_cpp::utils::GcmEncryptedData packet;
        std::copy(iv.begin(), iv.begin()+packet.iv.size(), packet.iv.begin());
        std::vector<uint8_t> ct_vec(ct.begin(), ct.end());
        packet.ciphertext = ct_vec;
        std::copy(tag.begin(), tag.begin()+packet.tag.size(), packet.tag.begin());

        auto plain_vec = aes_cpp::utils::decrypt_gcm(packet, key, aad_bytes);
        hmac_cpp::secure_zero(key.data(), key.size());
        hmac_cpp::secure_zero(ct_vec.data(), ct_vec.size());
        auto fields = split(std::string(plain_vec.begin(), plain_vec.end()), ':');
        hmac_cpp::secure_zero(plain_vec.data(), plain_vec.size());
        if (fields.size() != 2) return false;
        out_email = fields[0];
        std::string pwd_tmp = fields[1];
        out_password = hmac_cpp::secret_string(pwd_tmp);
        hmac_cpp::secure_zero(&pwd_tmp[0], pwd_tmp.size());
        hmac_cpp::secure_zero(aad_bytes.data(), aad_bytes.size());
        return true;
    } catch (...) {
        return false;
    }
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
    std::cout << "Decrypted email: "    << out_email << std::endl;
    auto pass_out = out_password.reveal_copy();
    std::cout << "Decrypted password: " << pass_out << std::endl;
    hmac_cpp::secure_zero(&pass_out[0], pass_out.size());
    return 0;
}

