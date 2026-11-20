// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/cache.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

using binaryrat::ArtifactCache;
using nlohmann::json;

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

template <class Exception, class Action>
void requires_throw(Action action) {
    try { action(); }
    catch (const Exception&) { return; }
    throw std::runtime_error("expected exception was not thrown");
}

struct TemporaryDirectory {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
        ("binaryrat-cache-test-" + std::to_string(
             std::chrono::steady_clock::now().time_since_epoch().count()));
    TemporaryDirectory() { std::filesystem::create_directories(path); }
    ~TemporaryDirectory() { std::error_code e; std::filesystem::remove_all(path, e); }
};

// Holds records so they cannot be deleted or replaced, as a virus scanner or an indexer
// can: open handles without delete sharing on Windows, a read-only directory elsewhere.
// Not active when this process ignores file permissions (root).
class Pin {
public:
    Pin(const std::filesystem::path& root, [[maybe_unused]] const std::vector<std::filesystem::path>& records)
        : root_(root) {
#ifdef _WIN32
        held_.resize(records.size());
        active_ = true;
        for (std::size_t index = 0; index < records.size(); ++index) {
            held_[index].open(records[index], std::ios::binary);
            active_ = active_ && held_[index].is_open();
        }
#else
        std::filesystem::permissions(root_, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_exec);
        const auto probe = root_ / "probe";
        { std::ofstream output(probe); active_ = !output; }
        std::error_code ignored;
        if (!active_) std::filesystem::remove(probe, ignored);
#endif
    }
    Pin(const Pin&) = delete;
    Pin& operator=(const Pin&) = delete;
    ~Pin() {
#ifdef _WIN32
        for (auto& handle : held_) handle.close();
#else
        std::error_code ignored;
        std::filesystem::permissions(root_, std::filesystem::perms::owner_all, ignored);
#endif
    }
    [[nodiscard]] bool active() const { return active_; }

private:
    std::filesystem::path root_;
    bool active_ = false;
#ifdef _WIN32
    std::vector<std::ifstream> held_;
#endif
};

json key(int id) {
    return {{"program", "fixture"}, {"function", id}, {"semantic_state", "epoch-1"}};
}

void identity_and_restart() {
    TemporaryDirectory directory;
    {
        ArtifactCache cache(directory.path);
        require(!cache.get(key(1)), "new artifact must miss");
        cache.put(key(1), {{"c", "int f(void) { return 1; }"}}, {"f:1", "type:int"});
        require(cache.get(key(1))->at("c") == "int f(void) { return 1; }", "roundtrip");
        auto changed = key(1);
        changed["semantic_state"] = "epoch-2";
        require(!cache.get(changed), "semantic state must participate in identity");
    }
    ArtifactCache restarted(directory.path);
    require(restarted.get(key(1)).has_value(), "artifacts must survive restart");
    restarted.put(key(1), {{"c", "replacement"}}, {"f:1"});
    require(restarted.get(key(1))->at("c") == "replacement", "atomic replacement");
    const auto a = json::parse(R"({"z":1,"a":{"c":3,"b":2}})");
    const auto b = json::parse(R"({"a":{"b":2,"c":3},"z":1})");
    require(ArtifactCache::key_digest(a) == ArtifactCache::key_digest(b),
            "key insertion order must not change identity");
    require(ArtifactCache::key_digest(json::object()) ==
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        "SHA-256 must match an independent known vector");
    requires_throw<std::invalid_argument>([&] { (void) restarted.get(json::array()); });
    requires_throw<std::invalid_argument>([&] {
        restarted.put({{"number", std::numeric_limits<double>::quiet_NaN()}}, "bad");
    });
    requires_throw<std::invalid_argument>([&] {
        restarted.put(key(2), std::numeric_limits<double>::infinity());
    });
}

void dependency_invalidation() {
    TemporaryDirectory directory;
    ArtifactCache cache(directory.path);
    cache.put(key(1), 1, {"callee:2", "callee:2", "type:A"});
    cache.put(key(2), 2, {"type:B"});
    cache.put(key(3), 3, {"type:A"});
    require(cache.invalidate({}) == 0, "empty invalidation preserves all entries");
    require(cache.invalidate({"unknown"}) == 0, "unrelated changes preserve entries");
    require(cache.invalidate({"type:A", "callee:2"}) == 2,
            "one entry matching multiple dependencies must count once");
    require(!cache.get(key(1)) && !cache.get(key(3)), "affected entries must miss");
    require(cache.get(key(2)).value() == 2, "unaffected artifact must survive");
    require(cache.invalidate({"type:A"}) == 0, "invalidation must be idempotent");
}

void corruption_limits_and_paths() {
    TemporaryDirectory directory;
    ArtifactCache cache(directory.path, 1024);
    cache.put(key(1), {{"c", "original"}}, {"f:1"});
    const auto path = directory.path / (ArtifactCache::key_digest(key(1)) + ".json");
    json record;
    { std::ifstream input(path); input >> record; }
    record["payload"]["value"]["c"] = "tampered";
    { std::ofstream output(path); output << record.dump(); }
    require(!cache.get(key(1)), "checksum mismatch must miss, not expose changed output");
    require(cache.invalidate({"f:1"}) == 0, "corrupt cleanup is not a valid invalidation");
    require(!std::filesystem::exists(path), "corrupt artifacts removed on invalidation");
    { std::ofstream output(path); output << "{partial"; }
    require(!cache.get(key(1)), "truncated record must miss");
    cache.put(key(1), "small");
    requires_throw<std::length_error>([&] { cache.put(key(1), std::string(2048, 'x')); });
    require(cache.get(key(1)).value() == "small", "rejected update must preserve old data");
    { std::ofstream output(path); output << std::string(2048, 'x'); }
    require(!cache.get(key(1)), "oversized on-disk record must miss");

    // Serializing a record recurses once per nesting level, so one nested deeper than any
    // request can be is refused even when everything else about it is right.
    const auto written = [&](const json& value) {
        json payload{{"schema_version", 1}, {"key", key(1)}, {"value", value},
                     {"dependencies", json::array()}};
        json record{{"payload", payload}, {"checksum", ArtifactCache::key_digest(payload)}};
        std::ofstream output(path);
        output << record.dump();
    };
    json nested = "leaf";
    for (int level = 0; level < 100; ++level) nested = json::array({nested});
    written(json::array({"leaf"}));
    require(cache.get(key(1)).value() == json::array({"leaf"}), "a well-formed record written by hand is read");
    written(nested);
    require(!cache.get(key(1)), "a record nested deeper than any request must miss");

    const auto id = ArtifactCache::key_digest(key(1));
    requires_throw<std::invalid_argument>([&] { cache.remove("subdir/" + id); });
    requires_throw<std::invalid_argument>([&] { cache.remove((directory.path / id).string()); });

    const json unsafe{{"path", "../../outside"}};
    cache.put(unsafe, "safe");
    require(cache.get(unsafe).value() == "safe", "untrusted key text is not a path");
    for (const auto& entry : std::filesystem::directory_iterator(directory.path)) {
        require(entry.path().parent_path() == directory.path, "all artifacts remain inside root");
        require(entry.path().extension() == ".json", "successful writes leave no temporary file");
    }
}

// A record the engine cannot write or delete must fail that one request with a message
// that names the operation but no path, keep the old record, and never stop a scan.
void records_that_cannot_be_changed() {
    TemporaryDirectory directory;
    ArtifactCache cache(directory.path);
    const auto unique_name = directory.path.filename().string();
    const auto refused = [&](auto action, const char* operation) {
        try {
            action();
        } catch (const std::system_error& error) {
            const std::string text = error.what();
            require(text.find(operation) != std::string::npos, "the refusal names the operation");
            require(text.find(unique_name) == std::string::npos, "the refusal names no cache path");
            return;
        }
        throw std::runtime_error(std::string("expected a refused ") + operation);
    };

    // A directory where a record belongs: the write fails everywhere, without privileges.
    const auto squatted = directory.path / (ArtifactCache::key_digest(key(1)) + ".json");
    std::filesystem::create_directory(squatted);
    { std::ofstream output(squatted / "occupied"); output << "x"; }
    refused([&] { cache.put(key(1), "value"); }, "replace cache record");
    require(!cache.get(key(1)), "a refused write stores nothing");
    require(cache.scan().empty(), "a directory is never indexed");
    require(!cache.remove(ArtifactCache::key_digest(key(1))), "a directory is not a record to remove");
    for (const auto& entry : std::filesystem::directory_iterator(directory.path)) {
        require(entry.path() == squatted, "a refused write leaves no temporary file");
    }
    std::filesystem::remove_all(squatted);

    cache.put(key(2), "kept", {"f:2"});
    const auto id = ArtifactCache::key_digest(key(2));
    const auto corrupt = directory.path / (ArtifactCache::key_digest(key(3)) + ".json");
    { std::ofstream output(corrupt); output << "{partial"; }
    {
        Pin pin(directory.path, {directory.path / (id + ".json"), corrupt});
        if (!pin.active()) {
            std::cout << "cache pinning skipped: this process ignores file permissions" << std::endl;
            return;
        }
        refused([&] { cache.remove(id); }, "remove cache record");
        refused([&] { cache.put(key(2), "changed", {"f:2"}); }, "cache record");
        const auto stored = cache.scan();
        require(stored.size() == 1 && stored[0].id == id, "a corrupt record that cannot be deleted is skipped");
        require(std::filesystem::exists(corrupt), "the held corrupt record is left in place");
        require(cache.get(key(2)).value() == "kept", "a refused update keeps the old record");
    }
    require(cache.scan().size() == 1 && !std::filesystem::exists(corrupt),
            "a released corrupt record is deleted by the next scan");
    require(cache.remove(id) && !cache.get(key(2)), "a released record can be removed");
}

void concurrent_access() {
    TemporaryDirectory directory;
    ArtifactCache cache(directory.path);
    std::vector<std::future<void>> tasks;
    for (int thread = 0; thread < 4; ++thread) {
        tasks.push_back(std::async(std::launch::async, [&, thread] {
            for (int i = 0; i < 25; ++i) {
                const auto id = thread * 25 + i;
                cache.put(key(id), {{"id", id}}, {"group:" + std::to_string(thread)});
                require(cache.get(key(id))->at("id") == id, "concurrent roundtrip");
            }
        }));
    }
    for (auto& task : tasks) task.get();
    require(cache.invalidate({"group:1"}) == 25, "concurrent writes retain dependencies");
    require(cache.get(key(0)).has_value() && !cache.get(key(25)), "selective invalidation");
}
} // namespace

int main() {
    try {
        identity_and_restart();
        dependency_invalidation();
        corruption_limits_and_paths();
        records_that_cannot_be_changed();
        concurrent_access();
        std::cout << "cache tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "cache test failed: " << error.what() << '\n';
        return 1;
    }
}
