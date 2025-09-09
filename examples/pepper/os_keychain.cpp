// Cross-platform keychain helper.
//
// The implementation relies on native APIs on each platform:
//  * Windows: DPAPI with registry-backed storage.
//  * macOS: Keychain Services.
//  * Linux: `secret-tool` (libsecret) command line utility.

#include "os_keychain.hpp"

#include <obfy/obfy_str.hpp>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#elif defined(__APPLE__)
#include <Security/Security.h>
#endif

namespace pepper::os_keychain {

    static std::string obfuscate_id(const std::string& id) {
        std::hash<std::string> h;
        std::ostringstream oss;
        oss << std::hex << h(id);
        return std::string(OBFY_STR("pepper-")) + oss.str();
    }

#if defined(_WIN32)

    bool available() {
        DATA_BLOB in{0, nullptr};
        DATA_BLOB out{0, nullptr};
        if (!CryptProtectData(&in, L"", nullptr, nullptr, nullptr, 0, &out)) {
            std::cerr << "CryptProtectData failed: " << GetLastError() << '\n';
            return false;
        }
        if (out.pbData) LocalFree(out.pbData);
        return true;
    }

    bool store(const std::string& key_id, const std::vector<uint8_t>& data) {
        auto obf = obfuscate_id(key_id);
        std::wstring name(obf.begin(), obf.end());
        DATA_BLOB in{static_cast<DWORD>(data.size()), const_cast<BYTE*>(data.data())};
        DATA_BLOB out{0, nullptr};
        if (!CryptProtectData(&in, name.c_str(), nullptr, nullptr, nullptr, 0, &out)) {
            std::cerr << "CryptProtectData failed: " << GetLastError() << '\n';
            return false;
        }
        HKEY hk{};
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\pepper", 0, nullptr, 0, KEY_WRITE, nullptr, &hk, nullptr) != ERROR_SUCCESS) {
            std::cerr << "RegCreateKeyEx failed: " << GetLastError() << '\n';
            if (out.pbData) LocalFree(out.pbData);
            return false;
        }
        if (RegSetValueExW(hk, name.c_str(), 0, REG_BINARY, out.pbData, out.cbData) != ERROR_SUCCESS) {
            std::cerr << "RegSetValueEx failed: " << GetLastError() << '\n';
            RegCloseKey(hk);
            if (out.pbData) LocalFree(out.pbData);
            return false;
        }
        RegCloseKey(hk);
        if (out.pbData) LocalFree(out.pbData);
        return true;
    }

    bool load(const std::string& key_id, std::vector<uint8_t>& out_data) {
        auto obf = obfuscate_id(key_id);
        std::wstring name(obf.begin(), obf.end());
        HKEY hk{};
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\pepper", 0, KEY_READ, &hk) != ERROR_SUCCESS) {
            std::cerr << "RegOpenKeyEx failed: " << GetLastError() << '\n';
            return false;
        }
        DWORD size = 0; DWORD type = 0;
        if (RegGetValueW(hk, nullptr, name.c_str(), RRF_RT_REG_BINARY, &type, nullptr, &size) != ERROR_SUCCESS) {
            std::cerr << "RegGetValue size failed: " << GetLastError() << '\n';
            RegCloseKey(hk);
            return false;
        }
        std::vector<BYTE> enc(size);
        if (RegGetValueW(hk, nullptr, name.c_str(), RRF_RT_REG_BINARY, &type, enc.data(), &size) != ERROR_SUCCESS) {
            std::cerr << "RegGetValue data failed: " << GetLastError() << '\n';
            RegCloseKey(hk);
            return false;
        }
        RegCloseKey(hk);
        DATA_BLOB in{size, enc.data()};
        DATA_BLOB out{0, nullptr};
        if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
            std::cerr << "CryptUnprotectData failed: " << GetLastError() << '\n';
            return false;
        }
        out_data.assign(out.pbData, out.pbData + out.cbData);
        if (out.pbData) LocalFree(out.pbData);
        return true;
    }

#elif defined(__APPLE__)

    bool available() {
        SecKeychainRef kc = nullptr;
        OSStatus st = SecKeychainCopyDefault(&kc);
        if (st != errSecSuccess) {
            std::cerr << "Keychain unavailable: " << st << '\n';
            return false;
        }
        if (kc) CFRelease(kc);
        return true;
    }

    bool store(const std::string& key_id, const std::vector<uint8_t>& data) {
        auto obf = obfuscate_id(key_id);
        OSStatus st = SecKeychainAddGenericPassword(nullptr,
            static_cast<UInt32>(obf.size()), obf.c_str(),
            0, nullptr,
            static_cast<UInt32>(data.size()), data.data(),
            nullptr);
        if (st != errSecSuccess) {
            std::cerr << "Keychain add failed: " << st << '\n';
            return false;
        }
        return true;
    }

    bool load(const std::string& key_id, std::vector<uint8_t>& out_data) {
        auto obf = obfuscate_id(key_id);
        void* data = nullptr; UInt32 len = 0; SecKeychainItemRef item = nullptr;
        OSStatus st = SecKeychainFindGenericPassword(nullptr,
            static_cast<UInt32>(obf.size()), obf.c_str(),
            0, nullptr,
            &len, &data, &item);
        if (st != errSecSuccess) {
            std::cerr << "Keychain find failed: " << st << '\n';
            return false;
        }
        out_data.assign(static_cast<uint8_t*>(data), static_cast<uint8_t*>(data) + len);
        SecKeychainItemFreeContent(nullptr, data);
        if (item) CFRelease(item);
        return true;
    }

#else // Linux

    static std::string to_hex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (auto b : data)
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        return oss.str();
    }

    static std::vector<uint8_t> from_hex(const std::string& hex) {
        std::vector<uint8_t> out; out.reserve(hex.size()/2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            uint8_t v = static_cast<uint8_t>(std::stoi(hex.substr(i,2), nullptr, 16));
            out.push_back(v);
        }
        return out;
    }

    bool available() {
        int r = std::system("secret-tool --version >/dev/null 2>&1");
        if (r != 0) {
            std::cerr << "secret-tool unavailable: " << r << '\n';
            return false;
        }
        return true;
    }

    bool store(const std::string& key_id, const std::vector<uint8_t>& data) {
        auto obf = obfuscate_id(key_id);
        std::string hex = to_hex(data);
        std::string cmd = "secret-tool store --label=pepper key " + obf;
        FILE* p = popen(cmd.c_str(), "w");
        if (!p) {
            std::cerr << "popen store failed: " << errno << '\n';
            return false;
        }
        if (fwrite(hex.data(), 1, hex.size(), p) != hex.size()) {
            std::cerr << "secret-tool write failed\n";
            pclose(p);
            return false;
        }
        int code = pclose(p);
        if (code != 0) {
            std::cerr << "secret-tool store error: " << code << '\n';
            return false;
        }
        return true;
    }

    bool load(const std::string& key_id, std::vector<uint8_t>& out_data) {
        auto obf = obfuscate_id(key_id);
        std::string cmd = "secret-tool lookup key " + obf;
        FILE* p = popen(cmd.c_str(), "r");
        if (!p) {
            std::cerr << "popen lookup failed: " << errno << '\n';
            return false;
        }
        std::string hex; char buf[256];
        while (fgets(buf, sizeof(buf), p)) hex += buf;
        int code = pclose(p);
        if (code != 0) {
            std::cerr << "secret-tool lookup error: " << code << '\n';
            return false;
        }
        hex.erase(std::remove(hex.begin(), hex.end(), '\n'), hex.end());
        out_data = from_hex(hex);
        return !out_data.empty();
    }

#endif

} // namespace pepper::os_keychain
