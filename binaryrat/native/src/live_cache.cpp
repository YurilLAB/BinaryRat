// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/live_cache.hpp>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace binaryrat {

LiveCache::LiveCache(ArtifactCache& store, std::size_t journal_limit)
    : store_(store), journal_limit_(journal_limit) {
    if (journal_limit_ == 0) throw std::invalid_argument("journal_limit must be positive");
    for (auto& stored : store_.scan()) index(stored.id, std::move(stored.dependencies), 0);
}

void LiveCache::index(const std::string& id, std::vector<std::string> dependencies,
                      std::uint64_t generation) {
    unindex(id);
    std::sort(dependencies.begin(), dependencies.end());
    dependencies.erase(std::unique(dependencies.begin(), dependencies.end()), dependencies.end());
    // Install the forward list first so unindex can unwind a partial reverse index.
    const auto entry = dependencies_of_.emplace(id, Indexed{std::move(dependencies), generation}).first;
    for (const auto& dependency : entry->second.dependencies) dependents_[dependency].insert(id);
}

void LiveCache::unindex(const std::string& id) {
    const auto found = dependencies_of_.find(id);
    if (found == dependencies_of_.end()) return;
    for (const auto& dependency : found->second.dependencies) {
        const auto users = dependents_.find(dependency);
        if (users == dependents_.end()) continue;
        users->second.erase(id);
        if (users->second.empty()) dependents_.erase(users);
    }
    dependencies_of_.erase(found);
    verified_at_.erase(id);
}

bool LiveCache::remove(const std::string& id) {
    const bool removed = store_.remove(id);
    unindex(id);
    return removed;
}

void LiveCache::journal(Journaled change) {
    journal_.push_back(std::move(change));
    while (journal_.size() > journal_limit_) {
        forgotten_seq_ = journal_.front().seq;
        journal_.pop_front();
    }
}

bool LiveCache::verified(const std::string& id) const {
    const auto found = verified_at_.find(id);
    return found != verified_at_.end() && found->second >= everything_seq_;
}

bool LiveCache::affected_since(std::uint64_t as_of,
                               const std::vector<std::string>& dependencies) const {
    if (as_of < forgotten_seq_ || as_of < everything_seq_) return true;
    for (const auto& change : journal_) {
        if (change.seq <= as_of) continue;
        if (change.everything) return true;
        for (const auto& dependency : dependencies)
            if (change.dependencies.contains(dependency)) return true;
    }
    return false;
}

LiveCache::Lookup LiveCache::get(const nlohmann::json& key) {
    const auto id = ArtifactCache::key_digest(key);
    std::lock_guard lock(mutex_);
    Lookup result;
    result.seq = seq_;
    auto value = store_.get(key);
    const auto found = dependencies_of_.find(id);
    if (!value || found == dependencies_of_.end()) {
        // A record that is unreadable, or that the index does not know, cannot be
        // invalidated reliably, so it is dropped rather than served.
        if (value || found != dependencies_of_.end()) remove(id);
        ++counters_.misses;
        return result;
    }
    result.hit = true;
    result.value = std::move(*value);
    result.verified = verified(id);
    result.generation = found->second.generation;
    ++counters_.hits;
    if (!result.verified) ++counters_.unverified_hits;
    return result;
}

void LiveCache::put(const nlohmann::json& key, const nlohmann::json& value,
                    const std::vector<std::string>& dependencies,
                    std::optional<std::uint64_t> as_of) {
    const auto id = ArtifactCache::key_digest(key);
    std::lock_guard lock(mutex_);
    if (as_of && *as_of > seq_) throw std::invalid_argument("as_of is ahead of the change sequence");
    store_.put(key, value, dependencies);
    try {
        index(id, dependencies, ++generation_);
        if (!as_of || !affected_since(*as_of, dependencies)) verified_at_[id] = seq_;
    } catch (...) {
        // The file was already replaced. A failed index update must not leave
        // this value verified against its predecessor's dependencies.
        unindex(id);
        throw;
    }
}

LiveCache::Change LiveCache::changed(const std::vector<std::string>& dependencies) {
    std::lock_guard lock(mutex_);
    Change result;
    result.seq = ++seq_;
    try {
        Journaled change;
        change.seq = seq_;
        std::unordered_set<std::string> affected;
        for (const auto& dependency : dependencies) {
            change.dependencies.insert(dependency);
            const auto users = dependents_.find(dependency);
            if (users != dependents_.end()) affected.insert(users->second.begin(), users->second.end());
        }
        for (const auto& id : affected) {
            if (remove(id)) {
                ++result.removed;
                ++counters_.removed;
            }
        }
        journal(std::move(change));
    } catch (...) {
        // A partial invalidation can leave affected records on disk. Force
        // replay for surviving records and for work started before this change.
        everything_seq_ = result.seq;
        throw;
    }
    return result;
}

LiveCache::Change LiveCache::changed_all() {
    std::lock_guard lock(mutex_);
    Change result;
    result.seq = ++seq_;
    everything_seq_ = seq_;
    Journaled change;
    change.seq = seq_;
    change.everything = true;
    journal(std::move(change));
    return result;
}

bool LiveCache::confirm(const nlohmann::json& key, std::uint64_t seq, std::uint64_t generation) {
    const auto id = ArtifactCache::key_digest(key);
    std::lock_guard lock(mutex_);
    if (seq > seq_) throw std::invalid_argument("seq is ahead of the change sequence");
    const auto found = dependencies_of_.find(id);
    // A different generation means the record was rewritten after it was checked.
    if (found == dependencies_of_.end() || found->second.generation != generation) return false;
    auto& at = verified_at_[id];
    at = std::max(at, seq);
    return true;
}

bool LiveCache::evict(const nlohmann::json& key) {
    const auto id = ArtifactCache::key_digest(key);
    std::lock_guard lock(mutex_);
    const bool removed = remove(id);
    if (removed) ++counters_.removed;
    return removed;
}

LiveCache::Stats LiveCache::stats() const {
    std::lock_guard lock(mutex_);
    Stats result = counters_;
    result.entries = dependencies_of_.size();
    for (const auto& entry : dependencies_of_)
        if (verified(entry.first)) ++result.verified;
    result.dependencies = dependents_.size();
    result.journal = journal_.size();
    result.seq = seq_;
    return result;
}

} // namespace binaryrat
