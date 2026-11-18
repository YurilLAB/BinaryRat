// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/admission.hpp>

#include "deadline.hpp"

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <exception>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace binaryrat {

std::uint64_t native_pool_bytes(const Budget& budget) noexcept {
    constexpr auto max = std::numeric_limits<std::uint64_t>::max();
    const std::uint64_t reserves = budget.jvm_reserve_bytes > max - budget.other_reserve_bytes
        ? max
        : budget.jvm_reserve_bytes + budget.other_reserve_bytes;
    return budget.ram_bytes > reserves ? budget.ram_bytes - reserves : 0;
}

std::size_t worker_limit(const Budget& budget) {
    if (budget.cpu_workers == 0 || budget.worker_cap == 0 || budget.worker_bytes == 0) {
        throw std::invalid_argument("budget requires positive cpu_workers, worker_cap and worker_bytes");
    }
    const std::uint64_t by_ram = native_pool_bytes(budget) / budget.worker_bytes;
    const std::uint64_t limit = std::min<std::uint64_t>(
        {budget.cpu_workers, budget.worker_cap, by_ram});
    return static_cast<std::size_t>(limit);
}

const char* to_string(Status status) noexcept {
    switch (status) {
        case Status::Completed: return "completed";
        case Status::Failed: return "failed";
        case Status::TimedOut: return "timed_out";
        case Status::Cancelled: return "cancelled";
        case Status::Rejected: return "rejected";
    }
    return "unknown";
}

namespace detail {

using Clock = std::chrono::steady_clock;

struct TaskState;
using WatchMap = std::multimap<Clock::time_point, std::shared_ptr<TaskState>>;

struct TaskState {
    enum class Phase { Queued, Running, Done };

    std::uint64_t reserved = 0;
    std::chrono::milliseconds timeout{0};
    std::function<void(std::stop_token)> job;
    std::stop_source stop;
    std::promise<Outcome> promise;

    // Guarded by Impl::mutex. The watch entry exists only while Running with a deadline.
    Phase phase = Phase::Queued;
    WatchMap::iterator watch_entry{};
    bool watched = false;

    // The first resolution wins; later ones are ignored.
    std::mutex result_mutex;
    bool resolved = false;

    void resolve(Status status, std::string message) {
        std::lock_guard lock(result_mutex);
        if (resolved) {
            return;
        }
        resolved = true;
        promise.set_value(Outcome{status, std::move(message)});
    }
};

namespace {
thread_local const Impl* current_impl = nullptr;

struct ExecutionContext {
    explicit ExecutionContext(const Impl* executor) : previous(current_impl) {
        current_impl = executor;
    }
    ~ExecutionContext() { current_impl = previous; }
    const Impl* previous;
};
}

// Lock order: Impl::mutex before TaskState::result_mutex. result_mutex is never
// held while taking Impl::mutex.
struct Impl {
    Impl(const Budget& budget, std::size_t pending_limit)
        : max_pending(pending_limit),
          pool_bytes(native_pool_bytes(budget)),
          worker_bytes(budget.worker_bytes),
          worker_count(worker_limit(budget)) {
        if (pending_limit == 0) {
            throw std::invalid_argument("executor requires a positive queue capacity");
        }
        if (worker_count == 0) {
            throw ResourceExhausted("native memory budget cannot hold a single worker");
        }
    }

    const std::size_t max_pending;
    const std::uint64_t pool_bytes;
    const std::uint64_t worker_bytes;
    const std::size_t worker_count;

    mutable std::mutex mutex;
    std::mutex shutdown_mutex;
    std::condition_variable ready;     // workers: new work, freed memory, shutdown
    std::condition_variable space;     // submitters: free queue slot, shutdown
    std::condition_variable watch_cv;  // watchdog: new deadline, stop
    std::deque<std::shared_ptr<TaskState>> pending;
    WatchMap watch;
    std::uint64_t reserved = 0;
    std::uint64_t peak_reserved = 0;
    std::size_t running = 0;
    std::size_t peak_running = 0;
    bool stopping = false;
    bool watch_stop = false;
    std::vector<std::thread> threads;
    std::thread watchdog;

    void start() {
        try {
            threads.reserve(worker_count);
            for (std::size_t i = 0; i < worker_count; ++i) {
                threads.emplace_back([this] { worker_loop(); });
            }
            watchdog = std::thread([this] { watchdog_loop(); });
        } catch (...) {
            {
                std::lock_guard lock(mutex);
                stopping = true;
                watch_stop = true;
            }
            ready.notify_all();
            watch_cv.notify_all();
            for (auto& thread : threads) {
                thread.join();
            }
            if (watchdog.joinable()) {
                watchdog.join();
            }
            throw;
        }
    }

    void enqueue(const std::shared_ptr<TaskState>& task) {
        if (task->reserved > pool_bytes) {
            task->resolve(Status::Rejected, "task reservation exceeds the native memory budget");
            return;
        }
        std::unique_lock lock(mutex);
        space.wait(lock, [this] { return stopping || pending.size() < max_pending; });
        if (stopping) {
            lock.unlock();
            task->resolve(Status::Rejected, "executor is shut down");
            return;
        }
        pending.push_back(task);
        lock.unlock();
        ready.notify_all();
    }

    void cancel(const std::shared_ptr<TaskState>& task) {
        std::unique_lock lock(mutex);
        switch (task->phase) {
            case TaskState::Phase::Queued: {
                const auto it = std::find(pending.begin(), pending.end(), task);
                if (it != pending.end()) {
                    pending.erase(it);
                }
                task->phase = TaskState::Phase::Done;
                lock.unlock();
                task->resolve(Status::Cancelled, "cancelled before the task started");
                space.notify_all();
                ready.notify_all();
                break;
            }
            case TaskState::Phase::Running:
                lock.unlock();
                // Decide the outcome before signalling: a job that reacts to the
                // stop instantly must not be able to resolve Completed first.
                task->resolve(Status::Cancelled, "cancelled while the task was running");
                signal_stop(*task);
                break;
            case TaskState::Phase::Done:
                break;
        }
    }

    void signal_stop(TaskState& task) {
        // request_stop invokes registered callbacks synchronously. No executor
        // lock may be held here, and callbacks must obey the same no-recursion
        // rule as jobs (including when cancellation came from a caller thread).
        ExecutionContext context(this);
        task.stop.request_stop();
    }

    void worker_loop() {
        current_impl = this;
        for (;;) {
            std::shared_ptr<TaskState> task;
            {
                std::unique_lock lock(mutex);
                ready.wait(lock, [this] {
                    if (pending.empty()) {
                        return stopping;
                    }
                    return pending.front()->reserved <= pool_bytes - reserved;
                });
                if (pending.empty()) {
                    return;  // stopping with nothing left to drain
                }
                task = std::move(pending.front());
                pending.pop_front();
                task->phase = TaskState::Phase::Running;
                reserved += task->reserved;
                ++running;
                peak_reserved = std::max(peak_reserved, reserved);
                peak_running = std::max(peak_running, running);
                if (task->timeout.count() > 0) {
                    task->watch_entry = watch.emplace(deadline_after(task->timeout), task);
                    task->watched = true;
                    watch_cv.notify_one();
                }
            }
            space.notify_all();

            Status status = Status::Completed;
            std::string message;
            try {
                task->job(task->stop.get_token());
            } catch (const std::exception& error) {
                status = Status::Failed;
                message = error.what();
            } catch (...) {
                status = Status::Failed;
                message = "unknown exception";
            }
            const auto finished_at = Clock::now();
            task->job = nullptr;  // release captured state on the worker, not the caller

            // Return capacity before resolving, so that a caller who sees a
            // Completed or Failed outcome also sees the memory already freed.
            // After this section the task can no longer time out or be cancelled.
            bool deadline_exceeded = false;
            {
                std::lock_guard lock(mutex);
                if (task->watched) {
                    // A busy or descheduled watchdog must not turn a job that
                    // returned after its deadline into Completed or Failed.
                    deadline_exceeded = finished_at >= task->watch_entry->first;
                    if (deadline_exceeded) {
                        status = Status::TimedOut;
                        message = "execution deadline exceeded";
                    }
                    watch.erase(task->watch_entry);
                    task->watched = false;
                }
                task->phase = TaskState::Phase::Done;
                reserved -= task->reserved;
                --running;
            }
            ready.notify_all();
            task->resolve(status, std::move(message));  // no-op if a timeout or cancel won already
            if (deadline_exceeded) {
                signal_stop(*task);
            }
        }
    }

    void watchdog_loop() {
        std::unique_lock lock(mutex);
        for (;;) {
            if (watch_stop) {
                return;
            }
            if (watch.empty()) {
                watch_cv.wait(lock);
                continue;
            }
            const auto first = watch.begin();
            // Copy the deadline: the map node can be erased by a finishing worker
            // while this thread sleeps with the mutex released.
            const Clock::time_point deadline = first->first;
            if (Clock::now() < deadline) {
                watch_cv.wait_until(lock, deadline);
                continue;
            }
            // Keep ownership after unlocking: the worker may return and release
            // its last reference as soon as the stop token is requested.
            auto task = first->second;
            watch.erase(first);
            task->watched = false;
            // Decide the outcome before signalling the job (see Impl::cancel).
            task->resolve(Status::TimedOut, "execution deadline exceeded");
            lock.unlock();
            signal_stop(*task);
            lock.lock();
        }
    }

    void shutdown(bool cancel_queued) {
        if (current_impl == this) {
            throw std::logic_error("a worker cannot shut down its own executor");
        }
        std::lock_guard serial(shutdown_mutex);
        std::vector<std::shared_ptr<TaskState>> discarded;
        {
            std::lock_guard lock(mutex);
            stopping = true;
            if (cancel_queued) {
                for (auto& task : pending) {
                    task->phase = TaskState::Phase::Done;
                }
                discarded.assign(std::make_move_iterator(pending.begin()),
                                 std::make_move_iterator(pending.end()));
                pending.clear();
            }
        }
        for (auto& task : discarded) {
            task->resolve(Status::Cancelled, "executor shut down before the task started");
        }
        ready.notify_all();
        space.notify_all();
        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        {
            std::lock_guard lock(mutex);
            watch_stop = true;  // deadlines stay enforced while workers drain
        }
        watch_cv.notify_all();
        if (watchdog.joinable()) {
            watchdog.join();
        }
    }

    Stats stats() const {
        std::lock_guard lock(mutex);
        Stats snapshot;
        snapshot.workers = worker_count;
        snapshot.pool_bytes = pool_bytes;
        snapshot.reserved_bytes = reserved;
        snapshot.peak_reserved_bytes = peak_reserved;
        snapshot.running = running;
        snapshot.peak_running = peak_running;
        snapshot.queued = pending.size();
        return snapshot;
    }
};

} // namespace detail

Ticket::Ticket(std::weak_ptr<detail::Impl> executor, std::shared_ptr<detail::TaskState> task)
    : result(task->promise.get_future()),
      executor_(std::move(executor)),
      task_(std::move(task)) {}

void Ticket::cancel() {
    if (const auto executor = executor_.lock()) {
        executor->cancel(task_);
    }
}

AdmissionExecutor::AdmissionExecutor(const Budget& budget, std::size_t max_pending)
    : impl_(std::make_shared<detail::Impl>(budget, max_pending)) {
    impl_->start();
}

AdmissionExecutor::~AdmissionExecutor() {
    impl_->shutdown(false);
}

Ticket AdmissionExecutor::submit(const TaskSpec& spec, std::function<void(std::stop_token)> job) {
    if (detail::current_impl == impl_.get()) {
        throw std::logic_error("a worker cannot submit recursively to its bounded executor");
    }
    if (!job) {
        throw std::invalid_argument("executor job must be callable");
    }
    if (spec.timeout.count() < 0) {
        throw std::invalid_argument("task timeout must not be negative");
    }
    auto task = std::make_shared<detail::TaskState>();
    task->job = std::move(job);
    task->timeout = spec.timeout;
    task->reserved = std::max(spec.reserve_bytes, impl_->worker_bytes);
    Ticket ticket(impl_, task);
    impl_->enqueue(task);
    return ticket;
}

void AdmissionExecutor::shutdown(bool cancel_queued) {
    impl_->shutdown(cancel_queued);
}

Stats AdmissionExecutor::stats() const {
    return impl_->stats();
}

} // namespace binaryrat
