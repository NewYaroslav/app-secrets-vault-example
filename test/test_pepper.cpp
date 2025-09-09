#include <cassert>
#include <vector>
#include <fstream>
#include <cstdint>

#include "../examples/pepper/pepper_provider.hpp"
#include "../examples/pepper/encrypted_file.hpp"

static std::vector<uint8_t> salt16() {
    std::vector<uint8_t> s(16);
    for (size_t i = 0; i < s.size(); ++i) s[i] = static_cast<uint8_t>(i + 1);
    return s;
}

static void test_machine_bound() {
    pepper::Config c1; c1.primary = pepper::StorageMode::MACHINE_BOUND; c1.app_salt = salt16();
    pepper::Provider p1(c1); std::vector<uint8_t> a; assert(p1.ensure(a)); assert(a.size()==32);
    pepper::Provider p1b(c1); std::vector<uint8_t> b; assert(p1b.ensure(b)); assert(a==b);
    pepper::Config c2 = c1; c2.app_salt[0] ^= 0xFF; pepper::Provider p2(c2); std::vector<uint8_t> c; assert(p2.ensure(c)); assert(a!=c);
}

static void test_encrypted_file() {
    pepper::Config cfg; cfg.primary = pepper::StorageMode::ENCRYPTED_FILE; cfg.file_path = "pepper_test.bin"; cfg.app_salt = salt16();
    { pepper::Provider p(cfg); std::vector<uint8_t> a; assert(p.ensure(a)); }
    pepper::Provider p2(cfg); std::vector<uint8_t> b; assert(p2.ensure(b));
    pepper::Provider p3(cfg); std::vector<uint8_t> c; assert(p3.load(c)); assert(b==c);
    std::ofstream(cfg.file_path, std::ios::binary|std::ios::trunc) << "bad";
    cfg.fallbacks.clear();
    pepper::Provider p4(cfg); std::vector<uint8_t> d; assert(!p4.load(d));
}

static void test_fallback() {
    pepper::Config cfg; cfg.primary = pepper::StorageMode::OS_KEYCHAIN; cfg.fallbacks = {pepper::StorageMode::MACHINE_BOUND}; cfg.app_salt = salt16();
    pepper::Provider p(cfg); std::vector<uint8_t> a; assert(p.ensure(a)); assert(a.size()==32);
}

int main() {
    test_machine_bound();
    test_encrypted_file();
    test_fallback();
    return 0;
}

