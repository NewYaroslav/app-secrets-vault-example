#include "machine_bound.hpp"
#include <hmac_cpp/sha256.hpp>
#include <fstream>
#include <cstdlib>

namespace pepper {
namespace machine_bound {

std::vector<uint8_t> get_machine_secret(const Config&) {
    std::ifstream f("/etc/machine-id");
    std::string id;
    if (f) {
        std::getline(f, id);
    }
    const char* user = std::getenv("USER");
    if (user) id += user;
    if (id.empty()) return {};
    return hmac_hash::sha256(id.data(), id.size());
}

} // namespace machine_bound
} // namespace pepper
