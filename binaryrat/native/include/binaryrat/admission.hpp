// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <stdexcept>
#include <stop_token>
#include <string>

namespace binaryrat {

// Resource budget for native analysis workers. All sizes are bytes.
//
//   workers <= min(cpu_workers, worker_cap,
//                  floor((ram_bytes - jvm_reserve_bytes - other_reserve_bytes)
//                        / worker_bytes))
//
// worker_bytes is the smallest memory reservation a single worker may hold.
struct Budget {
    std::size_t cpu_workers = 0;
    std::size_t worker_cap = 0;
    std::uint64_t ram_bytes = 0;
    std::uint64_t jvm_reserve_bytes = 0;
    std::uint64_t other_reserve_bytes = 0;
    std::uint64_t worker_bytes = 0;
};

// RAM left for native workers after the JVM and other analysis reserves.
// Saturates at zero instead of underflowing.
[[nodiscard]] std::uint64_t native_pool_bytes(const Budget& budget) noexcept;

// Number of workers the budget admits; zero when RAM cannot hold even one.
// Throws std::invalid_argument when cpu_workers, worker_cap or worker_bytes is zero.
[[nodiscard]] std::size_t worker_limit(const Budget& budget);

// The memory budget cannot hold a single worker.
class ResourceExhausted : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

enum class Status {
    Completed,  // the job returned normally
    Failed,     // the job threw; message holds what()
    TimedOut,   // the job's execution deadline passed first
    Cancelled,  // cancelled by the caller, or discarded by shutdown(true)
    Rejected,   // never admitted: reservation over budget, or executor shut down
};

[[nodiscard]] const char* to_string(Status status) noexcept;

struct Outcome {
    Status status = Status::Completed;
    std::string message;
};

struct TaskSpec {
    // Memory this task holds while running. Raised to Budget::worker_bytes.
    std::uint64_t reserve_bytes = 0;
    // Execution deadline, counted from when the job starts, not from submission.
    // Zero means no deadline. Values beyond the steady clock's representable
    // range saturate at its maximum time point instead of overflowing.
    std::chrono::milliseconds timeout{0};
};

struct Stats {
    std::size_t workers = 0;
    std::uint64_t pool_bytes = 0;
    std::uint64_t reserved_bytes = 0;
    std::uint64_t peak_reserved_bytes = 0;
    std::size_t running = 0;
    std::size_t peak_running = 0;
    std::size_t queued = 0;
};

namespace detail {
struct Impl;
struct TaskState;
} // namespace detail

// Handle to one submitted task. result resolves exactly once.
class Ticket {
public:
    Ticket(std::weak_ptr<detail::Impl> executor, std::shared_ptr<detail::TaskState> task);

    std::future<Outcome> result;

    // A queued task is removed and resolves Cancelled at once. A running task
    // has its stop token requested and also resolves Cancelled at once. No-op
    // after the task has finished or the executor is gone.
    void cancel();

private:
    std::weak_ptr<detail::Impl> executor_;
    std::shared_ptr<detail::TaskState> task_;
};

// Runs jobs on at most worker_limit(budget) threads while keeping the sum of
// running reservations within the native memory pool.
//
// Admission is strict FIFO: a queued task that does not fit waits and so do the
// tasks behind it, so large tasks cannot be starved. At most max_pending tasks
// queue; submit() blocks while the queue is full.
//
// Cancellation and timeouts are cooperative. When expiry is observed or a task
// is cancelled, its Outcome resolves and its stop token fires, but the
// job keeps its worker and its memory reservation until it actually returns. A
// job that ignores its stop token therefore never lets the executor exceed its
// budget; it only occupies capacity longer. For a job that returns or throws on
// its own, the capacity is freed before Completed or Failed becomes visible.
// Completion checks the deadline too, so a delayed watchdog cannot classify an
// over-deadline job as Completed. Notification is best-effort, not real-time;
// synchronous stop callbacks should return promptly to avoid delaying delivery.
//
// Jobs and synchronous stop callbacks must not submit to or shut down their own
// executor: blocking recursive use could deadlock a bounded executor, so these
// calls throw std::logic_error. Stop callbacks may query stats(); they are never
// invoked while holding the executor's state mutex.
class AdmissionExecutor {
public:
    // Throws ResourceExhausted when the budget cannot hold one worker, and
    // std::invalid_argument for a zero field or a zero max_pending.
    AdmissionExecutor(const Budget& budget, std::size_t max_pending);
    ~AdmissionExecutor();

    AdmissionExecutor(const AdmissionExecutor&) = delete;
    AdmissionExecutor& operator=(const AdmissionExecutor&) = delete;

    // Expected conditions come back as an Outcome (Rejected, Failed, ...).
    // Misuse (empty job, negative timeout, recursion) throws.
    [[nodiscard]] Ticket submit(const TaskSpec& spec, std::function<void(std::stop_token)> job);

    // Stops accepting work and waits for running jobs. Queued jobs are run to
    // completion, or resolved Cancelled when cancel_queued is true. Idempotent.
    void shutdown(bool cancel_queued = false);

    [[nodiscard]] Stats stats() const;

private:
    std::shared_ptr<detail::Impl> impl_;
};

} // namespace binaryrat
