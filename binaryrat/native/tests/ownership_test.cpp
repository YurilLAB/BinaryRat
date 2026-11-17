// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/ownership.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <system_error>

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

struct TemporaryDirectory {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
        ("binaryrat-ownership-test-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    ~TemporaryDirectory() { std::error_code e; std::filesystem::remove_all(path, e); }
};

void ownership_lifecycle() {
    TemporaryDirectory directory;
    {
        binaryrat::CacheOwnership owner(directory.path);
        require(std::filesystem::exists(directory.path / ".owner.lock"),
                "ownership creates its lock file");
        { std::ofstream artifact(directory.path / "artifact.json"); artifact << "sentinel"; }
        bool rejected = false;
        try { binaryrat::CacheOwnership second(directory.path); }
        catch (const std::system_error&) { rejected = true; }
        require(rejected, "a second owner must fail immediately");
        std::ifstream artifact(directory.path / "artifact.json");
        std::string value;
        artifact >> value;
        require(value == "sentinel", "ownership failure must not damage artifacts");
    }
    require(std::filesystem::exists(directory.path / ".owner.lock"),
            "lock file remains to avoid unlink races");
    binaryrat::CacheOwnership next(directory.path);
}

#ifndef _WIN32
void reject_symlink_lock() {
    TemporaryDirectory directory;
    std::filesystem::create_directories(directory.path);
    const auto target = directory.path / "target";
    { std::ofstream file(target); file << "unchanged"; }
    std::filesystem::create_symlink(target, directory.path / ".owner.lock");
    bool rejected = false;
    try { binaryrat::CacheOwnership owner(directory.path); }
    catch (const std::system_error&) { rejected = true; }
    require(rejected, "symlink ownership files must be rejected");
    std::ifstream file(target);
    std::string value;
    file >> value;
    require(value == "unchanged", "symlink target must not be changed");
}
#endif
} // namespace

int main() {
    try {
        ownership_lifecycle();
#ifndef _WIN32
        reject_symlink_lock();
#endif
        std::cout << "ownership tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ownership test failed: " << error.what() << '\n';
        return 1;
    }
}
