#ifndef PEPPER_PROVIDER_HPP
#define PEPPER_PROVIDER_HPP

#include <vector>
#include <string>
#include <cstdint>

namespace pepper {

// Where to keep the secret
enum class StorageMode {
    OS_KEYCHAIN,
    MACHINE_BOUND,
    ENCRYPTED_FILE
};

struct Config {
    StorageMode primary = StorageMode::OS_KEYCHAIN;
    std::vector<StorageMode> fallbacks = { StorageMode::MACHINE_BOUND, StorageMode::ENCRYPTED_FILE };
    std::string key_id = "pepper:v1";
    std::string file_path;
    bool use_os_wrap_if_possible = true;
    std::vector<uint8_t> app_salt; // 16..32 bytes
};

class Provider {
public:
    explicit Provider(const Config& cfg);
    ~Provider();

    bool ensure(std::vector<uint8_t>& out);
    bool load(std::vector<uint8_t>& out);

private:
    struct Impl;
    Impl* pimpl_;
};

} // namespace pepper

#endif // PEPPER_PROVIDER_HPP
