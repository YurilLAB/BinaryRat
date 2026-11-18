// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <binaryrat/cache.hpp>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

namespace binaryrat {

// A live view of an ArtifactCache for one session of a changing program.
//
// Every entry lists the program facts it was computed from (its dependencies).
// The program's owner reports each change as the dependencies it touched, or as
// a change of unknown reach:
//   - entries depending on a touched dependency are removed at once;
//   - a change of unknown reach makes every entry unverified.
// An unverified entry is still returned, flagged so: the caller must check it
// against the program (for decompiler output, by replaying the recorded reads)
// and then confirm() or evict() it. Entries left by earlier sessions start
// unverified, because changes made while no session was watching were never
// reported. Changes are numbered; a value computed while changes were arriving
// is stored with the number seen before computing it, and is kept unverified if
// a later change could have affected it.
class LiveCache {
public:
    explicit LiveCache(ArtifactCache& store, std::size_t journal_limit = 4096);

    struct Lookup {
        bool hit = false;       // a record exists for this key
        bool verified = false;  // no reported change can have affected it
        nlohmann::json value;
        std::uint64_t seq = 0;         // the current change number, for put() and confirm()
        std::uint64_t generation = 0;  // which write of this key was returned, for confirm()
    };
    [[nodiscard]] Lookup get(const nlohmann::json& key);

    // as_of: the change number observed before the value was computed. Without
    // it the caller asserts the value reflects the current program.
    void put(const nlohmann::json& key, const nlohmann::json& value,
             const std::vector<std::string>& dependencies, std::optional<std::uint64_t> as_of);

    struct Change {
        std::uint64_t seq = 0;
        std::size_t removed = 0;
    };
    Change changed(const std::vector<std::string>& dependencies);
    Change changed_all();

    // Marks the entry verified as of change number seq, both taken from get().
    // False when that write of the entry no longer exists.
    bool confirm(const nlohmann::json& key, std::uint64_t seq, std::uint64_t generation);
    bool evict(const nlohmann::json& key);

    struct Stats {
        std::size_t entries = 0;
        std::size_t verified = 0;
        std::size_t dependencies = 0;
        std::size_t journal = 0;
        std::uint64_t seq = 0;
        std::uint64_t hits = 0;
        std::uint64_t unverified_hits = 0;
        std::uint64_t misses = 0;
        std::uint64_t removed = 0;
    };
    [[nodiscard]] Stats stats() const;

private:
    struct Journaled {
        std::uint64_t seq = 0;
        bool everything = false;
        std::unordered_set<std::string> dependencies;
    };
    struct Indexed {
        std::vector<std::string> dependencies;
        std::uint64_t generation = 0;
    };

    void index(const std::string& id, std::vector<std::string> dependencies,
               std::uint64_t generation);
    void unindex(const std::string& id);
    bool remove(const std::string& id);
    void journal(Journaled change);
    [[nodiscard]] bool verified(const std::string& id) const;
    [[nodiscard]] bool affected_since(std::uint64_t as_of,
                                      const std::vector<std::string>& dependencies) const;

    ArtifactCache& store_;
    std::size_t journal_limit_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Indexed> dependencies_of_;
    std::unordered_map<std::string, std::unordered_set<std::string>> dependents_;
    std::unordered_map<std::string, std::uint64_t> verified_at_;
    std::deque<Journaled> journal_;
    std::uint64_t seq_ = 0;
    std::uint64_t generation_ = 0;
    std::uint64_t everything_seq_ = 0;  // last change of unknown reach
    std::uint64_t forgotten_seq_ = 0;   // changes up to here have left the journal
    Stats counters_;
};

} // namespace binaryrat
