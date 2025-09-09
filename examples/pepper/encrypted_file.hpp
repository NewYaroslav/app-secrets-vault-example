#ifndef PEPPER_ENCRYPTED_FILE_HPP
#define PEPPER_ENCRYPTED_FILE_HPP

#include <vector>
#include <string>
#include <cstdint>
#include "pepper_provider.hpp"

namespace pepper {
namespace encrypted_file {

bool load(const Config& cfg, std::vector<uint8_t>& out);
bool store(const Config& cfg, const std::vector<uint8_t>& data);

} // namespace encrypted_file
} // namespace pepper

#endif // PEPPER_ENCRYPTED_FILE_HPP
