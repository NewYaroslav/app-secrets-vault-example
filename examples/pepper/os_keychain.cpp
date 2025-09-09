#include "os_keychain.hpp"

#include <cstdint>

namespace pepper {
namespace os_keychain {

bool available() { return false; }

bool load(const std::string&, std::vector<uint8_t>&) { return false; }

bool store(const std::string&, const std::vector<uint8_t>&) { return false; }

} // namespace os_keychain
} // namespace pepper
