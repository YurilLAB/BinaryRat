// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <filesystem>

namespace binaryrat {

// Hold this guard for the entire lifetime of the engine's ArtifactCache. The OS
// releases ownership on process exit, including crashes; the empty lock file is
// retained to avoid unlink/recreate races. This is not an authentication boundary.
class CacheOwnership {
public:
    explicit CacheOwnership(const std::filesystem::path& root);
    ~CacheOwnership();

    CacheOwnership(const CacheOwnership&) = delete;
    CacheOwnership& operator=(const CacheOwnership&) = delete;
    CacheOwnership(CacheOwnership&&) = delete;
    CacheOwnership& operator=(CacheOwnership&&) = delete;

private:
    std::intptr_t handle_ = -1;
};

} // namespace binaryrat
