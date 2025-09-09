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
        OBFY_BEGIN_CODE
        std::vector<StorageMode> chain = {pimpl_->cfg.primary};
        chain.insert(chain.end(), pimpl_->cfg.fallbacks.begin(), pimpl_->cfg.fallbacks.end());
        for (auto mode : chain) {
            OBFY_CASE(mode)
                OBFY_WHEN(StorageMode::OS_KEYCHAIN) OBFY_DO
                    OBFY_IF(os_keychain::available())
                        if (OBFY_CALL(os_keychain::load, pimpl_->cfg.key_id, out)) OBFY_RETURN(true);
                    OBFY_ENDIF
                    OBFY_BREAK
                OBFY_DONE
                OBFY_WHEN(StorageMode::MACHINE_BOUND) OBFY_DO
                    if (derive_machine(pimpl_->cfg, out)) OBFY_RETURN(true);
                    OBFY_BREAK
                OBFY_DONE
                OBFY_WHEN(StorageMode::ENCRYPTED_FILE) OBFY_DO
                    if (encrypted_file::load(pimpl_->cfg, out)) OBFY_RETURN(true);
                    OBFY_BREAK
                OBFY_DONE
            OBFY_ENDCASE
        }
        OBFY_RETURN(false);
        OBFY_END_CODE
    }
    
    bool Provider::ensure(std::vector<uint8_t>& out) {
        OBFY_BEGIN_CODE
        std::vector<StorageMode> chain = {pimpl_->cfg.primary};
        chain.insert(chain.end(), pimpl_->cfg.fallbacks.begin(), pimpl_->cfg.fallbacks.end());
        for (auto mode : chain) {
            OBFY_CASE(mode)
                OBFY_WHEN(StorageMode::OS_KEYCHAIN) OBFY_DO
                    OBFY_IF(os_keychain::available())
                        if (OBFY_CALL(os_keychain::load, pimpl_->cfg.key_id, out)) OBFY_RETURN(true);
                        auto p = hmac_cpp::random_bytes(32);
                        if (p.size() != 32) OBFY_RETURN(false); // ERR_RNG
                        if (OBFY_CALL(os_keychain::store, pimpl_->cfg.key_id, p)) { out = p; OBFY_RETURN(true); }
                    OBFY_ENDIF
                    OBFY_BREAK
                OBFY_DONE
                OBFY_WHEN(StorageMode::MACHINE_BOUND) OBFY_DO
                    if (derive_machine(pimpl_->cfg, out)) OBFY_RETURN(true);
                    OBFY_BREAK
                OBFY_DONE
                OBFY_WHEN(StorageMode::ENCRYPTED_FILE) OBFY_DO
                    if (encrypted_file::load(pimpl_->cfg, out)) OBFY_RETURN(true);
                    auto p = hmac_cpp::random_bytes(32);
                    if (p.size() != 32) OBFY_RETURN(false); // ERR_RNG
                    if (encrypted_file::store(pimpl_->cfg, p)) { out = p; OBFY_RETURN(true); }
                    OBFY_BREAK
                OBFY_DONE
            OBFY_ENDCASE
        }
        OBFY_RETURN(false);
        OBFY_END_CODE
    }

} // namespace pepper
