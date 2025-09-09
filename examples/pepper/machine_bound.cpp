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
        #ifdef _WIN32
        char* user = nullptr;
        size_t user_sz = 0;
        if (_dupenv_s(&user, &user_sz, "USERNAME") == 0 && user) {
            id += user;
            free(user);
        }
        #else
        if (const char* user = std::getenv("USER")) id += user;
        #endif
        if (id.empty()) return {};
        auto ms = hmac_hash::sha256(id.data(), id.size());
        hmac_cpp::secure_zero(id.data(), id.size());
        id.clear();
        auto out = ms;
        hmac_cpp::secure_zero(ms.data(), ms.size());
        return out;
    }

} // namespace pepper::machine_bound
