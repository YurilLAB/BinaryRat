// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <binaryrat/admission.hpp>
#include <binaryrat/host.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>

namespace binaryrat {

// How the scheduler reads and stops the processes that do a lease's work.
// Tests substitute a fake; production uses the host functions.
class ProcessProbe {
public:
    virtual ~ProcessProbe() = default;
    virtual std::optional<host::ProcessId> identify(std::uint64_t pid) = 0;
    virtual std::optional<std::uint64_t> resident_bytes(const host::ProcessId& process) = 0;
    virtual bool terminate(const host::ProcessId& process) = 0;
};

[[nodiscard]] std::shared_ptr<ProcessProbe> system_process_probe();

enum class LeaseStatus { Completed, TimedOut, Cancelled, MemoryExceeded, Failed, Rejected };
enum class StopReason { Timeout, Cancelled, Memory, Shutdown };

[[nodiscard]] const char* to_string(LeaseStatus status) noexcept;
[[nodiscard]] const char* to_string(StopReason reason) noexcept;

struct LeaseOptions {
    // Memory the job may use. Raised to Budget::worker_bytes. It is both the
    // admission reservation and the resident-memory ceiling of an attached process.
    std::uint64_t reserve_bytes = 0;
    // Counted from the grant. Zero means no deadline.
    std::chrono::milliseconds timeout{0};
};

struct LeaseGrant {
    std::string lease;
    std::chrono::milliseconds waited{0};
    std::uint64_t reserve_bytes = 0;
};

struct LeaseEnd {
    std::string lease;
    LeaseStatus status = LeaseStatus::Completed;
    std::string message;
    std::chrono::milliseconds ran{0};  // from grant to release
    std::uint64_t peak_resident_bytes = 0;
    bool killed = false;
};

struct LeaseCallbacks {
    // The lease was admitted. Runs on an executor worker; must not block for long.
    std::function<void(const LeaseGrant&)> granted;
    // The lease will never run: rejected by the budget, or cancelled while queued.
    std::function<void(const LeaseEnd&)> not_granted;
};

struct SchedulerEvents {
    // A running lease must stop: deadline, cancel, memory ceiling, or shutdown.
    std::function<void(const std::string& lease, StopReason reason)> stopped;
    // The holder did not release within the grace period, so the attached
    // process was killed.
    std::function<void(const std::string& lease, std::uint64_t pid)> killed;
};

struct SchedulerOptions {
    Budget budget;
    std::size_t max_pending = 4096;
    std::chrono::milliseconds memory_poll{50};
    // After a stop, how long the holder has to release before its attached
    // process is killed. Zero never kills.
    std::chrono::milliseconds kill_grace{5000};
    std::shared_ptr<ProcessProbe> probe;  // null: system_process_probe()
};

struct AttachResult {
    bool attached = false;
    std::string reason;
    std::uint64_t resident_bytes = 0;
};

struct SchedulerStats {
    Stats executor;
    std::size_t queued = 0;
    std::size_t running = 0;
    std::uint64_t granted = 0;
    std::uint64_t completed = 0;
    std::uint64_t timed_out = 0;
    std::uint64_t cancelled = 0;
    std::uint64_t memory_exceeded = 0;
    std::uint64_t failed = 0;
    std::uint64_t rejected = 0;
    std::uint64_t killed = 0;
};

// Named leases on an AdmissionExecutor, for work done outside this process (a
// decompiler run by the JVM). A lease holds one worker and its memory
// reservation from grant to release. The holder learns of deadlines, cancels and
// memory overruns through SchedulerEvents::stopped and must then stop its work
// and release; a holder that does not release within kill_grace has its attached
// process killed. Leases are acquired, attached, released and cancelled from one
// controlling thread; callbacks and events arrive on other threads.
class LeaseScheduler {
public:
    LeaseScheduler(SchedulerOptions options, SchedulerEvents events);
    ~LeaseScheduler();

    LeaseScheduler(const LeaseScheduler&) = delete;
    LeaseScheduler& operator=(const LeaseScheduler&) = delete;

    // Queues a lease. Throws std::invalid_argument for an empty or duplicate
    // name, a negative timeout or a full queue, and std::logic_error after
    // shutdown. A lease the budget can never hold is reported through
    // not_granted before this returns.
    void acquire(const std::string& lease, const LeaseOptions& options, LeaseCallbacks callbacks);

    // Watches the resident memory of the process doing the lease's work.
    // Replaces an earlier attachment. Throws for a lease that is not running.
    AttachResult attach(const std::string& lease, std::uint64_t pid);

    // Ends a granted lease and reports how it ended. Throws std::invalid_argument
    // for an unknown lease or one that has not been granted yet.
    LeaseEnd release(const std::string& lease);

    // Cancels a queued or running lease. False when the lease is unknown.
    bool cancel(const std::string& lease);

    // Cancels everything, waits for running jobs to return. Idempotent.
    void shutdown();

    [[nodiscard]] SchedulerStats stats() const;
    [[nodiscard]] std::size_t workers() const noexcept { return workers_; }
    [[nodiscard]] const Budget& budget() const noexcept { return options_.budget; }

private:
    struct State;

    void run(const std::shared_ptr<State>& state, std::stop_token token);
    void request_stop(const std::shared_ptr<State>& state, StopReason reason);
    void watch_memory();
    std::shared_ptr<State> find(const std::string& lease) const;
    void count(LeaseStatus status);

    SchedulerOptions options_;
    SchedulerEvents events_;
    std::size_t workers_ = 0;
    std::unique_ptr<AdmissionExecutor> executor_;

    mutable std::mutex mutex_;  // guards leases_ and the counters
    std::unordered_map<std::string, std::shared_ptr<State>> leases_;
    SchedulerStats counters_;
    std::atomic<bool> shutting_down_{false};

    std::mutex watch_mutex_;
    std::condition_variable watch_wake_;
    bool watch_stop_ = false;
    std::thread watcher_;
};

} // namespace binaryrat
