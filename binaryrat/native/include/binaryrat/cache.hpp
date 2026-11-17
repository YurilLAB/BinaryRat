// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace binaryrat {

// Persistent, content-addressed artifacts for one owning process. The caller must
// include every semantic dependency stamp in the key. Dependency names support
// explicit invalidation; they do not prove that the key is complete.
class ArtifactCache {
public:
    explicit ArtifactCache(std::filesystem::path root,
                           std::size_t max_entry_bytes = 16 * 1024 * 1024);

    void put(const nlohmann::json& key, const nlohmann::json& value,
             const std::vector<std::string>& dependencies = {});
    [[nodiscard]] std::optional<nlohmann::json> get(const nlohmann::json& key);
    std::size_t invalidate(const std::vector<std::string>& dependencies);

    [[nodiscard]] static std::string key_digest(const nlohmann::json& key);

private:
    [[nodiscard]] std::optional<nlohmann::json> read_record(
        const std::filesystem::path& path) const;

    std::filesystem::path root_;
    std::size_t max_entry_bytes_;
    std::mutex mutex_;
};

} // namespace binaryrat
