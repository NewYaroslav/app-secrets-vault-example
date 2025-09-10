#pragma once
#include <string>
#include <filesystem>
#include <stdexcept>
#include <vector>
#include <hmac_cpp/hmac_utils.hpp>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

namespace demo {

    inline void atomic_write_file(const std::string& path, const std::string& data) {
        namespace fs = std::filesystem;
        fs::path target(path);
        fs::path tmp = target;
        tmp += ".tmp";
#       ifdef _WIN32
        std::wstring wtmp = tmp.wstring();
        HANDLE h = CreateFileW(wtmp.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (h == INVALID_HANDLE_VALUE) throw std::runtime_error("open");
        DWORD written = 0;
        if (!WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) ||
            written != data.size()) {
            CloseHandle(h);
            DeleteFileW(wtmp.c_str());
            throw std::runtime_error("write");
        }
        if (!FlushFileBuffers(h)) {
            CloseHandle(h);
            DeleteFileW(wtmp.c_str());
            throw std::runtime_error("flush");
        }
        CloseHandle(h);
        std::wstring wfinal = target.wstring();
        if (!MoveFileExW(wtmp.c_str(), wfinal.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            DeleteFileW(wtmp.c_str());
            throw std::runtime_error("rename");
        }
        SetFileAttributesW(wfinal.c_str(), FILE_ATTRIBUTE_HIDDEN);
        HANDLE token = INVALID_HANDLE_VALUE;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            DeleteFileW(wfinal.c_str());
            throw std::runtime_error("token");
        }
        DWORD len = 0;
        if (!GetTokenInformation(token, TokenUser, nullptr, 0, &len)) {
            CloseHandle(token);
            DeleteFileW(wfinal.c_str());
            throw std::runtime_error("token");
        }
        std::vector<char> buf(len);
        if (!GetTokenInformation(token, TokenUser, buf.data(), len, &len)) {
            hmac_cpp::secure_zero(buf.data(), buf.size());
            CloseHandle(token);
            DeleteFileW(wfinal.c_str());
            throw std::runtime_error("token");
        }
        TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea.Trustee.ptstrName = (LPWSTR)tu->User.Sid;
        PACL acl = nullptr;
        if (SetEntriesInAclW(1, &ea, nullptr, &acl) != ERROR_SUCCESS) {
            hmac_cpp::secure_zero(buf.data(), buf.size());
            CloseHandle(token);
            DeleteFileW(wfinal.c_str());
            throw std::runtime_error("acl");
        }
        DWORD sec_res = SetNamedSecurityInfoW((LPWSTR)wfinal.c_str(), SE_FILE_OBJECT,
                                              DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
        LocalFree(acl);
        hmac_cpp::secure_zero(buf.data(), buf.size());
        CloseHandle(token);
        if (sec_res != ERROR_SUCCESS) {
            DeleteFileW(wfinal.c_str());
            throw std::runtime_error("acl");
        }
#       else
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) throw std::runtime_error("open");
        ssize_t written = ::write(fd, data.data(), data.size());
        if (written != static_cast<ssize_t>(data.size())) {
            ::close(fd);
            ::unlink(tmp.c_str());
            throw std::runtime_error("write");
        }
        if (::fsync(fd) != 0) {
            ::close(fd);
            ::unlink(tmp.c_str());
            throw std::runtime_error("fsync");
        }
        if (::close(fd) != 0) {
            ::unlink(tmp.c_str());
            throw std::runtime_error("close");
        }
        std::error_code ec;
        fs::rename(tmp, target, ec);
        if (ec) {
            ::unlink(tmp.c_str());
            throw std::runtime_error("rename");
        }
        if (::chmod(target.c_str(), 0600) != 0) {
            ::unlink(target.c_str());
            throw std::runtime_error("chmod");
        }
#       endif
    }

} // namespace demo
