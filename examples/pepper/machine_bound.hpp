#ifndef PEPPER_MACHINE_BOUND_HPP
#define PEPPER_MACHINE_BOUND_HPP

#include <vector>
#include "pepper_provider.hpp"

namespace pepper {
namespace machine_bound {

std::vector<uint8_t> get_machine_secret(const Config& cfg);

} // namespace machine_bound
} // namespace pepper

#endif // PEPPER_MACHINE_BOUND_HPP
