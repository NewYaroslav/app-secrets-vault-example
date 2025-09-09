#include "machine_bound.hpp"
#include <hmac_cpp/sha256.hpp>
#include <hmac_cpp/hmac_utils.hpp>
#include <fstream>
#include <cstdlib>

namespace pepper::machine_bound {

    std::vector<uint8_t> get_machine_secret(const Config&) {
        std::ifstream f("/etc/machine-id");
        std::string id;
        if (f) {
            std::getline(f, id);
        }
        const char* user = std::getenv("USER");
        if (user) id += user;
        if (id.empty()) return {};
        auto ms = hmac_hash::sha256(id.data(), id.size());
        hmac_cpp::secure_zero(id.data(), id.size());
        id.clear();
        auto out = ms;
        hmac_cpp::secure_zero(ms.data(), ms.size());
        return out;
    }

} // namespace pepper::machine_bound
