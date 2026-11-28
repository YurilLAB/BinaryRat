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

    struct Stored {
        std::string id;  // key_digest of the record's key
        std::vector<std::string> dependencies;
    };
    // Every valid record. Reclaims corrupt records and staging files from interrupted
    // writes; a file held open elsewhere that cannot be deleted stays unindexed.
    [[nodiscard]] std::vector<Stored> scan();
    // Removes the record stored under this key digest. True when one was removed; throws
    // std::system_error (whose message names no path) when it exists but cannot be removed.
    bool remove(const std::string& id);

    [[nodiscard]] static std::string key_digest(const nlohmann::json& key);

private:
    [[nodiscard]] std::optional<nlohmann::json> read_record(
        const std::filesystem::path& path) const;

    std::filesystem::path root_;
    std::size_t max_entry_bytes_;
    std::mutex mutex_;
};

} // namespace binaryrat
