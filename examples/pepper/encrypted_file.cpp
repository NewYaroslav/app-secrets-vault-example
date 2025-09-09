#include "encrypted_file.hpp"
#include "machine_bound.hpp"

#include <aes_cpp/aes_utils.hpp>
#include <hmac_cpp/hmac_utils.hpp>
#include <obfy/obfy_str.hpp>
#include <obfy/obfy_bytes.hpp>

#include <fstream>
#include <array>
#include <algorithm>
#include <cstdlib>

namespace pepper::encrypted_file {

    static std::string resolve_path(const Config& cfg) {
        if (!cfg.file_path.empty()) return cfg.file_path;
        #ifdef _WIN32
        char* home = nullptr;
        size_t home_sz = 0;
        if (_dupenv_s(&home, &home_sz, "USERPROFILE") == 0 && home) {
            std::string path(home);
            free(home);
            return path + "\\pepper.bin";
        }
        #else
        if (const char* home = std::getenv("HOME")) {
            return std::string(home) + "/pepper.bin";
        }
        #endif
        return "pepper.bin";
    }
    
    bool store(const Config& cfg, const std::vector<uint8_t>& data) {
        auto path = resolve_path(cfg);
        if (data.size() != 32) return false;
        auto ms = machine_bound::get_machine_secret(cfg);
        if (ms.empty()) return false;
        auto prk = hmac_cpp::hkdf_extract_sha256(ms, cfg.app_salt);
        auto ctx = std::string(OBFY_STR("pepper-file"));
        auto key = hmac_cpp::hkdf_expand_sha256(prk, std::vector<uint8_t>(ctx.begin(), ctx.end()), 32);
        std::array<uint8_t,32> key_arr{};
        std::copy(key.begin(), key.end(), key_arr.begin());
        auto enc = aes_cpp::utils::encrypt_gcm(data, key_arr, {});
        if (enc.iv.size() != 12 || enc.ciphertext.size() != data.size() || enc.tag.size() != 16) {
            hmac_cpp::secure_zero(ms.data(), ms.size());
            hmac_cpp::secure_zero(prk.data(), prk.size());
            hmac_cpp::secure_zero(key.data(), key.size());
            hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
            hmac_cpp::secure_zero(enc.iv.data(), enc.iv.size());
            hmac_cpp::secure_zero(enc.ciphertext.data(), enc.ciphertext.size());
            hmac_cpp::secure_zero(enc.tag.data(), enc.tag.size());
            return false;
        }
        std::ofstream of(path.c_str(), std::ios::binary);
        if (!of) {
            hmac_cpp::secure_zero(ms.data(), ms.size());
            hmac_cpp::secure_zero(prk.data(), prk.size());
            hmac_cpp::secure_zero(key.data(), key.size());
            hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
            hmac_cpp::secure_zero(enc.iv.data(), enc.iv.size());
            hmac_cpp::secure_zero(enc.ciphertext.data(), enc.ciphertext.size());
            hmac_cpp::secure_zero(enc.tag.data(), enc.tag.size());
            return false;
        }
        auto magic = OBFY_BYTES("PPR1");
        of.write(reinterpret_cast<const char*>(magic),4);
        of.write(reinterpret_cast<const char*>(enc.iv.data()), enc.iv.size());
        of.write(reinterpret_cast<const char*>(enc.ciphertext.data()), enc.ciphertext.size());
        of.write(reinterpret_cast<const char*>(enc.tag.data()), enc.tag.size());
        bool ok = of.good();
        hmac_cpp::secure_zero(ms.data(), ms.size());
        hmac_cpp::secure_zero(prk.data(), prk.size());
        hmac_cpp::secure_zero(key.data(), key.size());
        hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
        hmac_cpp::secure_zero(enc.iv.data(), enc.iv.size());
        hmac_cpp::secure_zero(enc.ciphertext.data(), enc.ciphertext.size());
        hmac_cpp::secure_zero(enc.tag.data(), enc.tag.size());
        return ok;
    }
    
    bool load(const Config& cfg, std::vector<uint8_t>& out) {
        auto path = resolve_path(cfg);
        std::ifstream inf(path.c_str(), std::ios::binary);
        if (!inf) return false;
        char magic[4];
        inf.read(magic,4);
        auto expect = OBFY_BYTES("PPR1");
        if (std::string(magic,4) != std::string(reinterpret_cast<const char*>(expect),4)) return false;
        std::array<uint8_t,12> iv{};
        inf.read(reinterpret_cast<char*>(iv.data()), iv.size());
        std::vector<uint8_t> ct(32);
        inf.read(reinterpret_cast<char*>(ct.data()), ct.size());
        std::array<uint8_t,16> tag{};
        inf.read(reinterpret_cast<char*>(tag.data()), tag.size());
        if (!inf) {
            hmac_cpp::secure_zero(iv.data(), iv.size());
            hmac_cpp::secure_zero(ct.data(), ct.size());
            hmac_cpp::secure_zero(tag.data(), tag.size());
            return false;
        }
        auto ms = machine_bound::get_machine_secret(cfg);
        if (ms.empty()) return false;
        auto prk = hmac_cpp::hkdf_extract_sha256(ms, cfg.app_salt);
        auto ctx = std::string(OBFY_STR("pepper-file"));
        auto key = hmac_cpp::hkdf_expand_sha256(prk, std::vector<uint8_t>(ctx.begin(), ctx.end()), 32);
        std::array<uint8_t,32> key_arr{};
        std::copy(key.begin(), key.end(), key_arr.begin());
        aes_cpp::utils::GcmEncryptedData packet;
        packet.iv = iv;
        packet.ciphertext = ct;
        packet.tag = tag;
        out = aes_cpp::utils::decrypt_gcm(packet, key_arr, {});
        bool ok = out.size() == 32;
        hmac_cpp::secure_zero(ms.data(), ms.size());
        hmac_cpp::secure_zero(prk.data(), prk.size());
        hmac_cpp::secure_zero(key.data(), key.size());
        hmac_cpp::secure_zero(key_arr.data(), key_arr.size());
        hmac_cpp::secure_zero(ct.data(), ct.size());
        hmac_cpp::secure_zero(packet.ciphertext.data(), packet.ciphertext.size());
        if (!ok) {
            hmac_cpp::secure_zero(out.data(), out.size());
        }
        return ok;
    }

} // namespace pepper::encrypted_file
