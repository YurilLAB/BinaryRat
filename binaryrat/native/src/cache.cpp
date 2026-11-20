// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/cache.hpp>

#include "json_depth.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <picosha2/picosha2.h>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace binaryrat {
namespace {

std::string digest(const std::string& text) {
    return picosha2::hash256_hex_string(text);
}

std::string canonical_json(const nlohmann::json& value) {
    std::vector<const nlohmann::json*> pending{&value};
    while (!pending.empty()) {
        const auto* item = pending.back();
        pending.pop_back();
        if (item->is_binary() || item->is_discarded() ||
            (item->is_number_float() && !std::isfinite(item->get<double>()))) {
            throw std::invalid_argument("cache artifacts require finite, ordinary JSON values");
        }
        if (item->is_structured()) {
            for (const auto& child : *item) pending.push_back(&child);
        }
    }
    return value.dump();
}

bool artifact_filename(const std::filesystem::path& path) {
    const auto name = path.filename().string();
    return name.size() == 69 && name.substr(64) == ".json" &&
           std::all_of(name.begin(), name.begin() + 64, [](char ch) {
               return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
           });
}

// POSIX rename and Windows MoveFileEx replace the name atomically on the same
// filesystem. This promises complete records, not power-loss durability.
void replace_record(const std::filesystem::path& from,
                    const std::filesystem::path& to) {
#ifdef _WIN32
    if (!MoveFileExW(from.c_str(), to.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        throw std::system_error(static_cast<int>(GetLastError()),
                                std::system_category(), "replace cache record");
    }
#else
    // The error_code form keeps both paths out of the message the protocol returns.
    std::error_code error;
    std::filesystem::rename(from, to, error);
    if (error) throw std::system_error(error, "replace cache record");
#endif
}

std::filesystem::path temporary_path(const std::filesystem::path& root,
                                     const std::string& key) {
    static std::atomic<std::uint64_t> sequence{0};
    const auto time = std::chrono::steady_clock::now().time_since_epoch().count();
    return root / (key + ".tmp-" + std::to_string(time) + "-" +
                   std::to_string(sequence.fetch_add(1)));
}

} // namespace

ArtifactCache::ArtifactCache(std::filesystem::path root,
                             std::size_t max_entry_bytes)
    : root_(std::move(root)), max_entry_bytes_(max_entry_bytes) {
    if (root_.empty() || max_entry_bytes_ == 0) {
        throw std::invalid_argument("cache requires a directory and positive size limit");
    }
    std::filesystem::create_directories(root_);
    if (!std::filesystem::is_directory(root_)) {
        throw std::invalid_argument("cache root is not a directory");
    }
}

std::string ArtifactCache::key_digest(const nlohmann::json& key) {
    if (!key.is_object()) {
        throw std::invalid_argument("cache key must be an object");
    }
    // nlohmann::json uses ordered object keys (std::map), including nested ones.
    return digest(canonical_json(key));
}

void ArtifactCache::put(const nlohmann::json& key, const nlohmann::json& value,
                        const std::vector<std::string>& dependencies) {
    const auto id = key_digest(key);
    std::set<std::string> unique(dependencies.begin(), dependencies.end());
    nlohmann::json payload{{"schema_version", 1}, {"key", key}, {"value", value},
                           {"dependencies", unique}};
    nlohmann::json record{{"payload", payload}, {"checksum", digest(canonical_json(payload))}};
    const auto serialized = record.dump();
    if (serialized.size() > max_entry_bytes_) {
        throw std::length_error("cache artifact exceeds configured size limit");
    }

    std::lock_guard lock(mutex_);
    const auto temp = temporary_path(root_, id);
    try {
        {
            errno = 0;
            std::ofstream output(temp, std::ios::binary | std::ios::trunc);
            if (!output) {
                // A directory the engine may not write: name the operation, not the path.
                const int code = errno;
                throw std::system_error(code ? code : EIO, std::generic_category(), "write cache record");
            }
            output.exceptions(std::ios::badbit | std::ios::failbit);
            output.write(serialized.data(), static_cast<std::streamsize>(serialized.size()));
            output.close();
        }
        replace_record(temp, root_ / (id + ".json"));
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(temp, ignored);
        throw;
    }
}

std::optional<nlohmann::json> ArtifactCache::read_record(
    const std::filesystem::path& path) const {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        return std::nullopt;
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size > max_entry_bytes_) {
        return std::nullopt;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }
    // Bound the read itself as well as checking file_size, so external changes
    // cannot turn a small record into an unbounded allocation.
    std::string content;
    content.resize(static_cast<std::size_t>(size));
    input.read(content.data(), static_cast<std::streamsize>(content.size()));
    if (input.gcount() != static_cast<std::streamsize>(content.size()) ||
        input.peek() != std::char_traits<char>::eof()) {
        return std::nullopt;
    }
    // A record nests two levels deeper than the request that stored it.
    if (detail::json_nests_deeper_than(content, detail::maximum_json_depth + 2)) {
        return std::nullopt;
    }
    try {
        auto record = nlohmann::json::parse(content);
        if (!record.is_object() || !record.contains("payload") ||
            !record.contains("checksum") || !record["checksum"].is_string()) {
            return std::nullopt;
        }
        const auto& payload = record["payload"];
        if (!payload.is_object() || !payload.contains("schema_version") ||
            payload["schema_version"] != 1 ||
            !payload.contains("key") || !payload["key"].is_object() ||
            !payload.contains("value") || !payload.contains("dependencies") ||
            !payload["dependencies"].is_array() ||
            record["checksum"].get<std::string>() != digest(payload.dump()) ||
            path.filename().string() != key_digest(payload["key"]) + ".json") {
            return std::nullopt;
        }
        for (const auto& dependency : payload["dependencies"]) {
            if (!dependency.is_string()) {
                return std::nullopt;
            }
        }
        return payload;
    } catch (const nlohmann::json::exception&) {
        return std::nullopt;
    }
}

std::optional<nlohmann::json> ArtifactCache::get(const nlohmann::json& key) {
    const auto id = key_digest(key);
    std::lock_guard lock(mutex_);
    const auto record = read_record(root_ / (id + ".json"));
    if (!record || (*record)["key"] != key) {
        return std::nullopt;
    }
    return (*record)["value"];
}

std::vector<ArtifactCache::Stored> ArtifactCache::scan() {
    std::lock_guard lock(mutex_);
    std::vector<Stored> result;
    for (const auto& entry : std::filesystem::directory_iterator(root_)) {
        if (!artifact_filename(entry.path())) {
            continue;
        }
        const auto record = read_record(entry.path());
        if (!record) {
            // One that cannot be removed (a scanner holds it) stays unindexed: a read of
            // its key misses and a write replaces it, so it is never served. It must not
            // keep the engine from starting.
            if (!entry.is_symlink() && entry.is_regular_file()) {
                std::error_code ignored;
                std::filesystem::remove(entry.path(), ignored);
            }
            continue;
        }
        Stored stored;
        stored.id = entry.path().stem().string();
        for (const auto& dependency : (*record)["dependencies"]) {
            stored.dependencies.push_back(dependency.get<std::string>());
        }
        result.push_back(std::move(stored));
    }
    return result;
}

bool ArtifactCache::remove(const std::string& id) {
    const auto name = std::filesystem::path(id + ".json");
    if (name.has_parent_path() || !artifact_filename(name)) {
        throw std::invalid_argument("not a cache record id");
    }
    std::lock_guard lock(mutex_);
    std::error_code error;
    const auto status = std::filesystem::symlink_status(root_ / name, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        return false;
    }
    const bool removed = std::filesystem::remove(root_ / name, error);
    if (error) throw std::system_error(error, "remove cache record");
    return removed;
}

std::size_t ArtifactCache::invalidate(const std::vector<std::string>& dependencies) {
    if (dependencies.empty()) {
        return 0;
    }
    std::set<std::string> requested(dependencies.begin(), dependencies.end());
    std::lock_guard lock(mutex_);
    std::size_t removed = 0;
    for (const auto& entry : std::filesystem::directory_iterator(root_)) {
        if (!artifact_filename(entry.path())) {
            continue;
        }
        auto record = read_record(entry.path());
        if (!record) {
            // Corrupt named artifacts cannot safely participate in dependency
            // invalidation. Remove them so a later lookup always recomputes.
            if (!entry.is_symlink() && entry.is_regular_file()) {
                std::filesystem::remove(entry.path());
            }
            continue;
        }
        const auto& recorded = (*record)["dependencies"];
        const auto affected = std::any_of(recorded.begin(), recorded.end(),
            [&](const auto& dependency) {
                return requested.contains(dependency.template get<std::string>());
            });
        if (affected && std::filesystem::remove(entry.path())) {
            ++removed;
        }
    }
    return removed;
}

} // namespace binaryrat
