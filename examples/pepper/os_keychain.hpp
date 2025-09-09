#ifndef PEPPER_OS_KEYCHAIN_HPP
#define PEPPER_OS_KEYCHAIN_HPP

#include <vector>
#include <string>
#include <cstdint>

namespace pepper {
namespace os_keychain {

bool available();
bool load(const std::string& key_id, std::vector<uint8_t>& out);
bool store(const std::string& key_id, const std::vector<uint8_t>& data);

} // namespace os_keychain
} // namespace pepper

#endif // PEPPER_OS_KEYCHAIN_HPP
