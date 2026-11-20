// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/cache.hpp>
#include <binaryrat/live_cache.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <system_error>

// Inject a single failure when copying a long dependency in this test process.
// Ordinary allocations, including JSON cleanup, remain unaffected.
namespace {
thread_local int dependency_copies_before_failure = -1;
constexpr std::size_t dependency_length = 2039;
}

void* operator new(std::size_t size) {
    if (dependency_copies_before_failure >= 0 && size >= dependency_length + 1 &&
        size <= dependency_length + 32 && dependency_copies_before_failure-- == 0) {
        throw std::bad_alloc();
    }
    if (void* pointer = std::malloc(size == 0 ? 1 : size)) return pointer;
    throw std::bad_alloc();
}

void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { std::free(pointer); }

using namespace binaryrat;
using json = nlohmann::json;

namespace {
[[noreturn]] void fail(const std::string& message) {
    std::cerr << "live cache test failed: " << message << std::endl;
    std::_Exit(1);
}

void require(bool condition, const std::string& message) {
    if (!condition) fail(message);
}

template <class Exception, class Action>
void requires_throw(Action action, const std::string& message) {
    try {
        action();
    } catch (const Exception&) {
        return;
    }
    fail("expected exception: " + message);
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = std::filesystem::temp_directory_path() / ("binaryrat-live-" + std::to_string(stamp));
        std::filesystem::create_directories(path_);
    }
    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

json key(const std::string& address) {
    return {{"schema_version", 2}, {"ghidra_version", "12.2"}, {"kind", "decompile"},
            {"program_id", "sha256:p"}, {"address_space", "ram"}, {"address", address},
            {"options_digest", "o"}};
}

void precise_changes_remove_only_dependents() {
    TemporaryDirectory directory;
    ArtifactCache store(directory.path());
    LiveCache live(store);
    live.put(key("a"), {{"c", "A"}}, {"line:ram:10", "name:main"}, std::nullopt);
    live.put(key("b"), {{"c", "B"}}, {"line:ram:20"}, std::nullopt);
    auto found = live.get(key("a"));
    require(found.hit && found.verified && found.value["c"] == "A", "a fresh entry is a verified hit");
    const auto change = live.changed({"name:main", "line:ram:99"});
    require(change.removed == 1 && change.seq == 1, "only the dependent entry is removed");
    require(!live.get(key("a")).hit, "the removed entry misses");
    found = live.get(key("b"));
    require(found.hit && found.verified, "an unrelated entry stays verified");
    require(live.changed({"line:ram:20"}).removed == 1, "the second entry has its own dependency");
    require(live.stats().entries == 0 && live.stats().removed == 2, "stats count removals");
}

void unknown_changes_require_verification() {
    TemporaryDirectory directory;
    ArtifactCache store(directory.path());
    LiveCache live(store);
    live.put(key("a"), {{"c", "A"}}, {"line:ram:10"}, std::nullopt);
    live.changed_all();
    auto found = live.get(key("a"));
    require(found.hit && !found.verified, "a change of unknown reach leaves entries unverified");
    require(live.confirm(key("a"), found.seq, found.generation), "the caller confirms after checking");
    require(live.get(key("a")).verified, "a confirmed entry is verified");

    live.changed_all();
    found = live.get(key("a"));
    require(!found.verified, "unverified again after another unknown change");
    live.put(key("a"), {{"c", "A2"}}, {"line:ram:10"}, std::nullopt);
    require(!live.confirm(key("a"), found.seq, found.generation),
            "a confirmation for an older write of the entry is refused");
    require(live.get(key("a")).value["c"] == "A2", "the rewrite is kept");
    requires_throw<std::invalid_argument>([&] { live.confirm(key("a"), 999, 1); }, "seq from the future");

    const auto stale = live.get(key("a"));
    live.changed_all();
    require(live.confirm(key("a"), stale.seq, stale.generation), "confirming an old check is accepted");
    require(!live.get(key("a")).verified, "but it does not cover a later unknown change");
    require(live.evict(key("a")) && !live.get(key("a")).hit, "evict removes the entry");
    require(!live.confirm(key("a"), stale.seq, stale.generation), "nothing left to confirm");
}

void values_computed_during_changes_stay_unverified() {
    TemporaryDirectory directory;
    ArtifactCache store(directory.path());
    LiveCache live(store);
    const auto before = live.get(key("a")).seq;
    live.changed({"line:ram:50"});
    live.put(key("a"), {{"c", "A"}}, {"line:ram:10"}, before);
    require(live.get(key("a")).verified, "an unrelated change since as_of keeps the value verified");
    live.put(key("b"), {{"c", "B"}}, {"line:ram:50"}, before);
    require(live.get(key("b")).hit && !live.get(key("b")).verified,
            "a related change since as_of leaves the value unverified");
    const auto later = live.get(key("c")).seq;
    live.changed_all();
    live.put(key("c"), {{"c", "C"}}, {"line:ram:70"}, later);
    require(!live.get(key("c")).verified, "an unknown change since as_of leaves the value unverified");
    requires_throw<std::invalid_argument>(
        [&] { live.put(key("d"), {{"c", "D"}}, {"x"}, live.get(key("d")).seq + 1); }, "as_of from the future");
}

void failed_disk_invalidation_requires_revalidation() {
    TemporaryDirectory directory;
    ArtifactCache store(directory.path());
    LiveCache live(store);
    live.put(key("a"), "A", {"affected"}, std::nullopt);
    const auto before = live.get(key("a")).seq;
    const auto path = directory.path() / (ArtifactCache::key_digest(key("a")) + ".json");
    const auto dir_perms = std::filesystem::status(directory.path()).permissions();
    const auto file_perms = std::filesystem::status(path).permissions();
    std::filesystem::permissions(path, std::filesystem::perms::owner_read);
    std::filesystem::permissions(directory.path(), std::filesystem::perms::owner_read |
        std::filesystem::perms::owner_exec);
    bool failed = false;
    try {
        live.changed({"affected"});
    } catch (const std::system_error& error) {
        failed = std::string(error.what()).find("remove cache record") != std::string::npos;
        if (!failed) throw;
    }
    std::filesystem::permissions(directory.path(), dir_perms);
    if (std::filesystem::exists(path)) std::filesystem::permissions(path, file_perms);
    // Some hosts (e.g. a test running as root) can remove read-only records.
    if (!failed) return;
    require(!live.get(key("a")).verified, "failed invalidation must not serve stale verified data");
    live.put(key("b"), "old", {"affected"}, before);
    require(!live.get(key("b")).verified, "in-flight work must observe failed invalidation");
    require(live.changed({"affected"}).removed == 2, "retry removes both indexed records");
}

void allocation_failure_during_replacement_cannot_verify_stale_data() {
    const auto identity = key("a");
    const std::vector<std::string> dependencies{std::string(dependency_length, 'd')};
    bool failed_after_write = false;
    for (int site = 0; site < 128; ++site) {
        TemporaryDirectory directory;
        ArtifactCache store(directory.path());
        LiveCache live(store);
        live.put(identity, "old", {"old-dependency"}, std::nullopt);
        dependency_copies_before_failure = site;
        try {
            live.put(identity, "replacement", dependencies, std::nullopt);
        } catch (const std::bad_alloc&) {
            dependency_copies_before_failure = -1;
            if (store.get(identity) != "replacement") continue;
            failed_after_write = true;
            live.changed(dependencies);
            require(!live.get(identity).verified,
                    "failed reindex cannot serve a replacement using the old verified index");
            require(live.stats().dependencies == 0, "failed reindex leaves no dangling dependencies");
            continue;
        }
        dependency_copies_before_failure = -1;
        require(failed_after_write, "injected a dependency copy failure after persistent replacement");
        return;
    }
    fail("dependency allocation fault campaign did not terminate");
}

void forgotten_changes_are_treated_as_related() {
    TemporaryDirectory directory;
    ArtifactCache store(directory.path());
    LiveCache live(store, 2);
    const auto start = live.get(key("a")).seq;
    live.changed({"one"});
    live.changed({"two"});
    live.changed({"three"});
    require(live.stats().journal == 2, "the journal keeps its limit");
    live.put(key("a"), {{"c", "A"}}, {"unrelated"}, start);
    require(!live.get(key("a")).verified, "changes older than the journal may have mattered");
    live.put(key("b"), {{"c", "B"}}, {"unrelated"}, live.get(key("b")).seq - 1);
    require(live.get(key("b")).verified, "changes still in the journal are checked exactly");
}

void later_sessions_start_unverified_with_the_index_rebuilt() {
    TemporaryDirectory directory;
    {
        ArtifactCache store(directory.path());
        LiveCache live(store);
        live.put(key("a"), {{"c", "A"}}, {"line:ram:10"}, std::nullopt);
        live.put(key("b"), {{"c", "B"}}, {"line:ram:20"}, std::nullopt);
    }
    std::ofstream(directory.path() / (std::string(64, 'f') + ".json")) << "{not json";
    ArtifactCache store(directory.path());
    LiveCache live(store);
    require(!std::filesystem::exists(directory.path() / (std::string(64, 'f') + ".json")),
            "corrupt records are deleted when the index is built");
    auto found = live.get(key("a"));
    require(found.hit && !found.verified, "entries from an earlier session must be verified first");
    require(live.changed({"line:ram:10"}).removed == 1, "the rebuilt index still finds dependents");
    require(live.get(key("b")).hit, "other entries survive");
    const auto stats = live.stats();
    require(stats.entries == 1 && stats.verified == 0 && stats.unverified_hits == 2,
            "stats report unverified hits");
}

void index_follows_rewrites() {
    TemporaryDirectory directory;
    ArtifactCache store(directory.path());
    LiveCache live(store);
    live.put(key("a"), {{"c", "A"}}, {"old"}, std::nullopt);
    live.put(key("a"), {{"c", "A2"}}, {"new"}, std::nullopt);
    require(live.changed({"old"}).removed == 0, "a rewrite drops the old dependencies");
    require(live.changed({"new"}).removed == 1, "and indexes the new ones");
    require(live.stats().dependencies == 0, "no dependency is left pointing at nothing");
}

} // namespace

int main() {
    allocation_failure_during_replacement_cannot_verify_stale_data();
    precise_changes_remove_only_dependents();
    unknown_changes_require_verification();
    values_computed_during_changes_stay_unverified();
    failed_disk_invalidation_requires_revalidation();
    forgotten_changes_are_treated_as_related();
    later_sessions_start_unverified_with_the_index_rebuilt();
    index_follows_rewrites();
    std::cout << "live cache tests passed" << std::endl;
    return 0;
}
