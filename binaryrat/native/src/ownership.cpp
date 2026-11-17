// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/ownership.hpp>

#include <stdexcept>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace binaryrat {

CacheOwnership::CacheOwnership(const std::filesystem::path& root) {
    if (root.empty()) {
        throw std::invalid_argument("cache ownership requires a directory");
    }
    std::filesystem::create_directories(root);
    const auto path = root / ".owner.lock";
#ifdef _WIN32
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                                nullptr, OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT,
                                nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                "cache directory is already owned or inaccessible");
    }
    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(handle, &information)) {
        const auto error = GetLastError();
        CloseHandle(handle);
        throw std::system_error(static_cast<int>(error), std::system_category(),
                                "inspect cache ownership file");
    }
    if ((information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        CloseHandle(handle);
        throw std::runtime_error("cache ownership file must not be a reparse point");
    }
    handle_ = reinterpret_cast<std::intptr_t>(handle);
#else
    const int descriptor = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        throw std::system_error(errno, std::generic_category(), "open cache ownership file");
    }
    struct stat information{};
    if (::fstat(descriptor, &information) != 0) {
        const auto error = errno;
        ::close(descriptor);
        throw std::system_error(error, std::generic_category(), "inspect cache ownership file");
    }
    if (!S_ISREG(information.st_mode)) {
        ::close(descriptor);
        throw std::runtime_error("cache ownership file must be a regular file");
    }
    if (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        const auto error = errno;
        ::close(descriptor);
        throw std::system_error(error, std::generic_category(),
                                "cache directory is already owned or inaccessible");
    }
    handle_ = descriptor;
#endif
}

CacheOwnership::~CacheOwnership() {
    if (handle_ == -1) return;
#ifdef _WIN32
    CloseHandle(reinterpret_cast<HANDLE>(handle_));
#else
    ::close(static_cast<int>(handle_));
#endif
}

} // namespace binaryrat
