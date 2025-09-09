#include "pepper_provider.hpp"
#include "os_keychain.hpp"
#include "machine_bound.hpp"
#include "encrypted_file.hpp"

#include <hmac_cpp/hmac_utils.hpp>
#include <obfy/obfy_str.hpp>
#include <obfy/obfy_call.hpp>

namespace pepper {

    struct Provider::Impl {
        Config cfg;
        explicit Impl(const Config& c) : cfg(c) {}
    };
    
    Provider::Provider(const Config& cfg) : pimpl_(new Impl(cfg)) {}
    Provider::~Provider() { delete pimpl_; }
    
    static bool derive_machine(const Config& cfg, std::vector<uint8_t>& out) {
        auto ms = machine_bound::get_machine_secret(cfg);
        if (ms.empty()) return false;
        auto ctx = std::string(OBFY_STR("pepper:v1"));
        auto prk = hmac_cpp::hkdf_extract_sha256(ms, cfg.app_salt);
        auto key = hmac_cpp::hkdf_expand_sha256(prk, std::vector<uint8_t>(ctx.begin(), ctx.end()), 32);
        out = key;
        hmac_cpp::secure_zero(ms.data(), ms.size());
        hmac_cpp::secure_zero(prk.data(), prk.size());
        hmac_cpp::secure_zero(key.data(), key.size());
        return true;
    }
    
    bool Provider::load(std::vector<uint8_t>& out) {
        std::vector<StorageMode> chain = {pimpl_->cfg.primary};
        chain.insert(chain.end(), pimpl_->cfg.fallbacks.begin(), pimpl_->cfg.fallbacks.end());
        for (auto mode : chain) {
            if (mode == StorageMode::OS_KEYCHAIN) {
                if (os_keychain::available()) {
                    if (OBFY_CALL(os_keychain::load, pimpl_->cfg.key_id, out)) return true;
                }
            } else if (mode == StorageMode::MACHINE_BOUND) {
                if (derive_machine(pimpl_->cfg, out)) return true;
            } else if (mode == StorageMode::ENCRYPTED_FILE) {
                if (encrypted_file::load(pimpl_->cfg, out)) return true;
            }
        }
        return false;
    }
    
    bool Provider::ensure(std::vector<uint8_t>& out) {
        std::vector<StorageMode> chain = {pimpl_->cfg.primary};
        chain.insert(chain.end(), pimpl_->cfg.fallbacks.begin(), pimpl_->cfg.fallbacks.end());
        for (auto mode : chain) {
            if (mode == StorageMode::OS_KEYCHAIN) {
                if (os_keychain::available()) {
                    if (OBFY_CALL(os_keychain::load, pimpl_->cfg.key_id, out)) return true;
                    auto p = hmac_cpp::random_bytes(32);
                    if (OBFY_CALL(os_keychain::store, pimpl_->cfg.key_id, p)) { out = p; return true; }
                }
            } else if (mode == StorageMode::MACHINE_BOUND) {
                if (derive_machine(pimpl_->cfg, out)) return true;
            } else if (mode == StorageMode::ENCRYPTED_FILE) {
                if (encrypted_file::load(pimpl_->cfg, out)) return true;
                auto p = hmac_cpp::random_bytes(32);
                if (encrypted_file::store(pimpl_->cfg, p)) { out = p; return true; }
            }
        }
        return false;
    }

} // namespace pepper
