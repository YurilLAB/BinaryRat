// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/cache.hpp>
#include <binaryrat/host.hpp>
#include <binaryrat/live_cache.hpp>
#include <binaryrat/ownership.hpp>
#include <binaryrat/scheduler.hpp>
#include <binaryrat/types.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using json = nlohmann::json;
constexpr std::size_t maximum_line = 16 * 1024 * 1024;

// Responses and events come from the reading thread and from scheduler threads.
class Output {
public:
    void write(const json& line) {
        const auto text = line.dump();
        std::lock_guard lock(mutex_);
        std::cout << text << '\n' << std::flush;
        if (!std::cout) failed_ = true;
    }
    [[nodiscard]] bool failed() {
        std::lock_guard lock(mutex_);
        return failed_;
    }

private:
    std::mutex mutex_;
    bool failed_ = false;
};

json success(const json& id, json result) {
    return {{"id", id}, {"protocol_version", 1}, {"ok", true}, {"result", std::move(result)}};
}

json failure(const json& id, const char* code, const std::string& message) {
    return {{"id", id}, {"protocol_version", 1}, {"ok", false},
            {"error", {{"code", code}, {"message", message}}}};
}

std::string string_field(const json& object, const char* name) {
    if (!object.contains(name) || !object.at(name).is_string())
        throw std::invalid_argument(std::string(name) + " must be a string");
    return object.at(name).get<std::string>();
}

std::uint64_t unsigned_value(const json& value, const char* name) {
    if (!value.is_number_integer() ||
        (value.is_number_integer() && !value.is_number_unsigned() && value.get<std::int64_t>() < 0))
        throw std::invalid_argument(std::string(name) + " must be a nonnegative integer");
    return value.get<std::uint64_t>();
}

std::optional<std::uint64_t> optional_unsigned(const json& object, const char* name) {
    if (!object.contains(name) || object.at(name).is_null()) return std::nullopt;
    return unsigned_value(object.at(name), name);
}

std::chrono::milliseconds milliseconds_field(const json& object, const char* name,
                                             std::uint64_t fallback) {
    const auto value = optional_unsigned(object, name).value_or(fallback);
    if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max() / 1000))
        throw std::invalid_argument(std::string(name) + " is too large");
    return std::chrono::milliseconds(static_cast<std::int64_t>(value));
}

std::vector<std::string> dependencies(const json& request) {
    if (!request.contains("dependencies") || !request.at("dependencies").is_array())
        throw std::invalid_argument("dependencies must be an array of strings");
    std::vector<std::string> result;
    for (const auto& value : request.at("dependencies")) {
        if (!value.is_string() || value.get_ref<const std::string&>().empty())
            throw std::invalid_argument("dependency identities must be nonempty strings");
        result.push_back(value.get<std::string>());
    }
    return result;
}

// Schema 1 keys name a revision the caller vouches for. Schema 2 keys are live:
// they leave the program state out and rely on dependency tracking instead.
const json& cache_key(const json& request) {
    const auto& key = request.at("key");
    if (!key.is_object()) throw std::invalid_argument("key must be an object");
    if (!key.contains("schema_version") || !key.at("schema_version").is_number_integer())
        throw std::invalid_argument("unsupported cache schema or Ghidra version");
    const auto schema = unsigned_value(key.at("schema_version"), "schema_version");
    if (schema == 1) {
        for (const char* field : {"program_id", "address_space", "address", "body_sha256", "options_digest"})
            if (string_field(key, field).empty())
                throw std::invalid_argument(std::string("empty cache identity: ") + field);
        if (key.at("ghidra_version") != "12.2")
            throw std::invalid_argument("unsupported cache schema or Ghidra version");
        unsigned_value(key.at("revision"), "revision");
        return key;
    }
    if (schema == 2) {
        for (const char* field : {"ghidra_version", "kind", "program_id", "address_space", "address",
                                  "options_digest"})
            if (string_field(key, field).empty())
                throw std::invalid_argument(std::string("empty cache identity: ") + field);
        if (key.contains("revision"))
            throw std::invalid_argument("schema 2 keys must not name a revision");
        return key;
    }
    throw std::invalid_argument("unsupported cache schema or Ghidra version");
}

json recover_types(const json& request) {
    if (!request.at("observations").is_array())
        throw std::invalid_argument("observations must be an array");
    std::vector<binaryrat::types::AccessObservation> observations;
    for (const auto& item : request.at("observations")) {
        const auto& offset = item.at("offset");
        if (!offset.is_number_integer() || (offset.is_number_unsigned() &&
            offset.get<std::uint64_t>() > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())))
            throw std::invalid_argument("offset must fit a signed 64-bit integer");
        binaryrat::types::AccessObservation observation;
        observation.object_id = string_field(item, "object_id");
        observation.offset = offset.get<std::int64_t>();
        observation.width = unsigned_value(item.at("width"), "width");
        observation.evidence_id = string_field(item, "evidence_id");
        if (!item.at("object_start_known").is_boolean())
            throw std::invalid_argument("object_start_known must be boolean");
        observation.object_start_known = item.at("object_start_known").get<bool>();
        if (item.contains("stride") && !item.at("stride").is_null())
            observation.stride = unsigned_value(item.at("stride"), "stride");
        observations.push_back(std::move(observation));
    }
    binaryrat::types::LayoutRecoveryOptions options;
    if (request.contains("maximum_extent"))
        options.maximum_extent = unsigned_value(request.at("maximum_extent"), "maximum_extent");
    const auto recovered = binaryrat::types::recover_layouts(observations, options);
    json result = {{"layouts", json::array()}, {"rejected", json::array()},
                   {"score_kind", "uncalibrated_evidence_strength"}};
    for (const auto& layout : recovered.layouts) {
        json fields = json::array();
        for (const auto& field : layout.fields) {
            fields.push_back({{"offset", field.offset}, {"width", field.width},
                {"stride", field.stride ? json(*field.stride) : json(nullptr)},
                {"evidence_ids", field.evidence_ids}, {"evidence_strength", field.evidence_strength},
                {"overlaps_other_fields", field.overlaps_other_fields},
                {"stride_conflict", field.stride_conflict},
                {"stride_overlaps_access", field.stride_overlaps_access}});
        }
        result["layouts"].push_back({{"object_id", layout.object_id}, {"fields", fields},
            {"minimum_extent", layout.minimum_extent}, {"has_overlaps", layout.has_overlaps},
            {"has_stride_conflicts", layout.has_stride_conflicts},
            {"has_overlapping_stride", layout.has_overlapping_stride}});
    }
    for (const auto& rejection : recovered.rejected)
        result["rejected"].push_back({{"observation_index", rejection.observation_index},
                                      {"reason", binaryrat::types::to_string(rejection.reason)}});
    return result;
}

class Session {
public:
    Session(binaryrat::ArtifactCache& store, Output& output) : live_(store), output_(output) {}

    ~Session() { stop(); }

    void stop() {
        if (scheduler_) scheduler_->shutdown();
    }

    // Returns the result, or nullopt when the response is sent later.
    std::optional<json> dispatch(const json& request, const json& id) {
        const auto op = string_field(request, "op");
        if (request.contains("protocol_version") &&
            (!request.at("protocol_version").is_number_integer() ||
             unsigned_value(request.at("protocol_version"), "protocol_version") != 1))
            throw std::invalid_argument("protocol_version must be integer 1");
        if (op == "ping") return json{{"name", "BinaryRat"}, {"version", "0.1.0"},
            {"ghidra_version", "12.2"},
            {"capabilities", {"artifact-cache", "layout-proposals", "lease-scheduler", "live-cache"}}};
        if (op.starts_with("cache.")) return cache(op, request);
        if (op.starts_with("sched.")) return sched(op, request, id);
        if (op == "types.recover") return recover_types(request);
        throw std::invalid_argument("unknown operation: " + op);
    }

private:
    json cache(const std::string& op, const json& request) {
        if (op == "cache.put") {
            const auto as_of = optional_unsigned(request, "as_of");
            live_.put(cache_key(request), request.at("value"), dependencies(request), as_of);
            return {{"stored", true}};
        }
        if (op == "cache.get") {
            auto found = live_.get(cache_key(request));
            return {{"hit", found.hit}, {"verified", found.verified},
                    {"value", found.hit ? std::move(found.value) : json(nullptr)},
                    {"seq", found.seq}, {"generation", found.generation}};
        }
        if (op == "cache.invalidate" || op == "cache.changed") {
            const bool everything = op == "cache.changed" && request.contains("all") &&
                                    request.at("all") == true;
            const auto change = everything ? live_.changed_all() : live_.changed(dependencies(request));
            return {{"removed", change.removed}, {"seq", change.seq}};
        }
        if (op == "cache.confirm") {
            const auto seq = optional_unsigned(request, "seq");
            const auto generation = optional_unsigned(request, "generation");
            if (!seq || !generation) throw std::invalid_argument("seq and generation are required");
            return {{"confirmed", live_.confirm(cache_key(request), *seq, *generation)}};
        }
        if (op == "cache.evict") return {{"removed", live_.evict(cache_key(request))}};
        if (op == "cache.stats") {
            const auto stats = live_.stats();
            return {{"entries", stats.entries}, {"verified", stats.verified},
                    {"dependencies", stats.dependencies}, {"journal", stats.journal},
                    {"seq", stats.seq}, {"hits", stats.hits},
                    {"unverified_hits", stats.unverified_hits}, {"misses", stats.misses},
                    {"removed", stats.removed}};
        }
        throw std::invalid_argument("unknown operation: " + op);
    }

    binaryrat::LeaseScheduler& scheduler() {
        if (!scheduler_) throw std::invalid_argument("sched.configure must come first");
        return *scheduler_;
    }

    std::optional<json> sched(const std::string& op, const json& request, const json& id) {
        if (op == "sched.configure") return configure(request);
        if (op == "sched.acquire") {
            const auto lease = string_field(request, "lease");
            binaryrat::LeaseOptions options;
            options.reserve_bytes = optional_unsigned(request, "reserve_bytes").value_or(0);
            options.timeout = milliseconds_field(request, "timeout_ms", 0);
            binaryrat::LeaseCallbacks callbacks;
            callbacks.granted = [this, id](const binaryrat::LeaseGrant& grant) {
                output_.write(success(id, {{"granted", true}, {"lease", grant.lease},
                    {"waited_ms", grant.waited.count()}, {"reserve_bytes", grant.reserve_bytes}}));
            };
            callbacks.not_granted = [this, id](const binaryrat::LeaseEnd& end) {
                output_.write(success(id, {{"granted", false}, {"lease", end.lease},
                    {"status", to_string(end.status)}, {"message", end.message}}));
            };
            scheduler().acquire(lease, options, std::move(callbacks));
            return std::nullopt;
        }
        if (op == "sched.attach") {
            const auto pid = optional_unsigned(request, "pid");
            if (!pid) throw std::invalid_argument("pid is required");
            const auto attached = scheduler().attach(string_field(request, "lease"), *pid);
            json result = {{"attached", attached.attached}, {"resident_bytes", attached.resident_bytes}};
            if (!attached.attached) result["reason"] = attached.reason;
            return result;
        }
        if (op == "sched.release") {
            const auto end = scheduler().release(string_field(request, "lease"));
            return json{{"lease", end.lease}, {"status", to_string(end.status)},
                        {"message", end.message}, {"run_ms", end.ran.count()},
                        {"peak_resident_bytes", end.peak_resident_bytes}, {"killed", end.killed}};
        }
        if (op == "sched.cancel")
            return json{{"cancelled", scheduler().cancel(string_field(request, "lease"))}};
        if (op == "sched.stats") {
            const auto stats = scheduler().stats();
            return json{{"workers", scheduler().workers()}, {"queued", stats.queued},
                {"running", stats.running}, {"reserved_bytes", stats.executor.reserved_bytes},
                {"peak_reserved_bytes", stats.executor.peak_reserved_bytes},
                {"peak_running", stats.executor.peak_running}, {"pool_bytes", stats.executor.pool_bytes},
                {"granted", stats.granted}, {"completed", stats.completed},
                {"timed_out", stats.timed_out}, {"cancelled", stats.cancelled},
                {"memory_exceeded", stats.memory_exceeded}, {"failed", stats.failed},
                {"rejected", stats.rejected}, {"killed", stats.killed}};
        }
        throw std::invalid_argument("unknown operation: " + op);
    }

    json configure(const json& request) {
        if (scheduler_) throw std::invalid_argument("the scheduler is already configured");
        const auto machine = binaryrat::host::machine();
        binaryrat::SchedulerOptions options;
        auto& budget = options.budget;
        budget.cpu_workers = optional_unsigned(request, "cpu_workers").value_or(machine.logical_cpus);
        budget.worker_cap = optional_unsigned(request, "worker_cap").value_or(budget.cpu_workers);
        budget.ram_bytes = optional_unsigned(request, "ram_bytes").value_or(machine.physical_memory_bytes);
        if (budget.ram_bytes == 0)
            throw std::invalid_argument("physical memory is unknown here; ram_bytes is required");
        budget.jvm_reserve_bytes = optional_unsigned(request, "jvm_reserve_bytes").value_or(0);
        budget.other_reserve_bytes = optional_unsigned(request, "other_reserve_bytes").value_or(0);
        budget.worker_bytes = optional_unsigned(request, "worker_bytes").value_or(512ULL << 20);
        options.max_pending = optional_unsigned(request, "max_pending").value_or(4096);
        options.memory_poll = milliseconds_field(request, "memory_poll_ms", 50);
        options.kill_grace = milliseconds_field(request, "kill_grace_ms", 5000);
        binaryrat::SchedulerEvents events;
        events.stopped = [this](const std::string& lease, binaryrat::StopReason reason) {
            output_.write({{"event", "lease.stop"}, {"protocol_version", 1}, {"lease", lease},
                           {"reason", to_string(reason)}});
        };
        events.killed = [this](const std::string& lease, std::uint64_t pid) {
            output_.write({{"event", "lease.killed"}, {"protocol_version", 1}, {"lease", lease},
                           {"pid", pid}});
        };
        scheduler_ = std::make_unique<binaryrat::LeaseScheduler>(options, std::move(events));
        return {{"workers", scheduler_->workers()}, {"cpu_workers", budget.cpu_workers},
                {"worker_cap", budget.worker_cap}, {"ram_bytes", budget.ram_bytes},
                {"pool_bytes", binaryrat::native_pool_bytes(budget)},
                {"worker_bytes", budget.worker_bytes},
                {"machine", {{"logical_cpus", machine.logical_cpus},
                             {"physical_memory_bytes", machine.physical_memory_bytes}}},
                {"memory_watch", binaryrat::host::process_queries_supported()}};
    }

    binaryrat::LiveCache live_;
    Output& output_;
    std::unique_ptr<binaryrat::LeaseScheduler> scheduler_;
};

bool read_line(std::string& line, bool& oversized) {
    line.clear();
    oversized = false;
    char c;
    bool any = false;
    while (std::cin.get(c)) {
        any = true;
        if (c == '\n') break;
        if (line.size() < maximum_line) line.push_back(c);
        else oversized = true;
    }
    return any;
}

int serve(const std::filesystem::path& directory) {
    // Other threads write responses; reading must never flush std::cout itself.
    std::cin.tie(nullptr);
    binaryrat::CacheOwnership ownership(directory);
    binaryrat::ArtifactCache cache(directory);
    Output output;
    Session session(cache, output);
    std::string line;
    bool oversized;
    while (read_line(line, oversized)) {
        json id = nullptr;
        try {
            if (oversized) throw std::invalid_argument("request exceeds 16 MiB");
            const auto request = json::parse(line);
            if (!request.is_object()) throw std::invalid_argument("request must be an object");
            id = string_field(request, "id");
            if (auto result = session.dispatch(request, id)) output.write(success(id, std::move(*result)));
        } catch (const json::exception& error) {
            output.write(failure(id, "invalid_request", error.what()));
        } catch (const std::invalid_argument& error) {
            output.write(failure(id, "invalid_request", error.what()));
        } catch (const std::exception& error) {
            output.write(failure(id, "operation_failed", error.what()));
        }
        if (output.failed()) {
            session.stop();
            return 1;
        }
    }
    session.stop();
    return std::cin.bad() || output.failed() ? 1 : 0;
}
}

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
#else
int main(int argc, char** argv) {
#endif
    try {
        if (argc == 2 && std::filesystem::path(argv[1]) == "--version") {
            std::cout << "BinaryRat 0.1.0 (Ghidra 12.2; protocol 1)\n";
            return 0;
        }
        if (argc < 2 || std::filesystem::path(argv[1]) != "serve") {
            std::cerr << "Usage: binaryrat-engine --version | serve [--cache DIRECTORY]\n";
            return 2;
        }
        std::filesystem::path directory = ".binaryrat-cache";
        if (argc == 4 && std::filesystem::path(argv[2]) == "--cache") directory = argv[3];
        else if (argc != 2) throw std::invalid_argument("invalid command arguments");
        return serve(directory);
    } catch (const std::exception& error) {
        std::cerr << "BinaryRat: " << error.what() << '\n';
        return 1;
    }
}
