// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/scheduler.hpp>

#include "deadline.hpp"

#include <algorithm>
#include <new>
#include <stdexcept>
#include <utility>
#include <vector>

namespace binaryrat {
namespace {

using Clock = std::chrono::steady_clock;

class SystemProbe final : public ProcessProbe {
public:
    std::optional<host::ProcessId> identify(std::uint64_t pid) override {
        return host::identify(pid);
    }
    std::optional<std::uint64_t> resident_bytes(const host::ProcessId& process) override {
        return host::resident_bytes(process);
    }
    bool terminate(const host::ProcessId& process) override { return host::terminate(process); }
};

std::chrono::milliseconds between(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
}

template <typename Callback, typename... Args>
void notify(const Callback& callback, Args&&... args) noexcept {
    if (!callback) return;
    try {
        callback(std::forward<Args>(args)...);
    } catch (...) {
        // A failing observer must not take the lease or the executor down with it.
    }
}

} // namespace

std::shared_ptr<ProcessProbe> system_process_probe() {
    return std::make_shared<SystemProbe>();
}

const char* to_string(LeaseStatus status) noexcept {
    switch (status) {
    case LeaseStatus::Completed: return "completed";
    case LeaseStatus::TimedOut: return "timed_out";
    case LeaseStatus::Cancelled: return "cancelled";
    case LeaseStatus::MemoryExceeded: return "memory_exceeded";
    case LeaseStatus::Failed: return "failed";
    case LeaseStatus::Rejected: return "rejected";
    }
    return "unknown";
}

const char* to_string(StopReason reason) noexcept {
    switch (reason) {
    case StopReason::Timeout: return "timeout";
    case StopReason::Cancelled: return "cancelled";
    case StopReason::Memory: return "memory";
    case StopReason::Shutdown: return "shutdown";
    }
    return "unknown";
}

struct LeaseScheduler::State {
    std::string name;
    std::uint64_t reserve = 0;
    LeaseCallbacks callbacks;
    Clock::time_point requested = Clock::now();
    Clock::time_point granted_at{};
    std::shared_ptr<Ticket> ticket;       // cancel handle; set before acquire() returns
    std::shared_future<Outcome> outcome;  // set before acquire() returns

    std::mutex mutex;
    std::condition_variable wake;
    bool granted = false;   // the job started
    bool dropped = false;   // cancelled or rejected before it started
    bool released = false;
    bool finished = false;  // run() and any in-flight process termination have returned
    bool stop_seen = false;  // the executor requested a stop (deadline or cancel)
    std::optional<StopReason> reason;
    std::optional<host::ProcessId> process;
    std::uint64_t peak = 0;
    bool killed = false;
};

LeaseScheduler::LeaseScheduler(SchedulerOptions options, SchedulerEvents events)
    : options_(std::move(options)), events_(std::move(events)) {
    if (!options_.probe) options_.probe = system_process_probe();
    if (options_.max_pending == 0) throw std::invalid_argument("max_pending must be positive");
    if (options_.memory_poll.count() <= 0)
        throw std::invalid_argument("memory_poll must be positive");
    if (options_.kill_grace.count() < 0)
        throw std::invalid_argument("kill_grace must not be negative");
    workers_ = worker_limit(options_.budget);
    executor_ = std::make_unique<AdmissionExecutor>(options_.budget, options_.max_pending);
    // Allocate sampling slots before starting the watcher. Queued leases have
    // no process to measure and must not grow the watcher's allocation.
    std::vector<Attachment> attached;
    attached.reserve(workers_);
    watcher_ = std::thread(&LeaseScheduler::watch_memory, this, std::move(attached));
}

LeaseScheduler::~LeaseScheduler() {
    shutdown();
}

std::shared_ptr<LeaseScheduler::State> LeaseScheduler::find(const std::string& lease) const {
    std::lock_guard lock(mutex_);
    const auto found = leases_.find(lease);
    return found == leases_.end() ? nullptr : found->second;
}

void LeaseScheduler::count(LeaseStatus status) {
    std::lock_guard lock(mutex_);
    switch (status) {
    case LeaseStatus::Completed: ++counters_.completed; break;
    case LeaseStatus::TimedOut: ++counters_.timed_out; break;
    case LeaseStatus::Cancelled: ++counters_.cancelled; break;
    case LeaseStatus::MemoryExceeded: ++counters_.memory_exceeded; break;
    case LeaseStatus::Failed: ++counters_.failed; break;
    case LeaseStatus::Rejected: ++counters_.rejected; break;
    }
}

void LeaseScheduler::acquire(const std::string& lease, const LeaseOptions& options,
                             LeaseCallbacks callbacks) {
    if (lease.empty() || lease.size() > 256)
        throw std::invalid_argument("lease names must be 1 to 256 characters");
    if (options.timeout.count() < 0)
        throw std::invalid_argument("lease timeout must not be negative");
    if (shutting_down_) throw std::logic_error("scheduler is shut down");
    auto state = std::make_shared<State>();
    state->name = lease;
    state->reserve = std::max(options.reserve_bytes, options_.budget.worker_bytes);
    state->callbacks = std::move(callbacks);
    {
        std::lock_guard lock(mutex_);
        if (leases_.contains(lease))
            throw std::invalid_argument("lease name already in use: " + lease);
        // Only the controlling thread submits, so the queue can only shrink meanwhile
        // and submit() below never blocks the thread that must also read releases.
        if (executor_->stats().queued >= options_.max_pending)
            throw std::invalid_argument("lease queue is full");
        leases_.emplace(lease, state);
    }
    try {
        // The job holds the state weakly: the state owns the ticket, which owns the
        // executor's task, which owns this job, so a strong capture would be a cycle.
        auto ticket = std::make_shared<Ticket>(executor_->submit(
            TaskSpec{state->reserve, options.timeout},
            [this, weak = std::weak_ptr<State>(state)](std::stop_token token) {
                if (const auto held = weak.lock()) run(held, token);
            }));
        std::lock_guard lock(state->mutex);
        state->outcome = ticket->result.share();
        state->ticket = std::move(ticket);
    } catch (...) {
        std::lock_guard lock(mutex_);
        leases_.erase(lease);
        throw;
    }
    // A job that waits for its release cannot have finished yet, so a Rejected
    // outcome here means the budget can never admit it.
    if (state->outcome.wait_for(std::chrono::seconds(0)) == std::future_status::ready &&
        state->outcome.get().status == Status::Rejected) {
        {
            std::lock_guard lock(state->mutex);
            state->dropped = true;
        }
        {
            std::lock_guard lock(mutex_);
            leases_.erase(lease);
        }
        count(LeaseStatus::Rejected);
        LeaseEnd end;
        end.lease = lease;
        end.status = LeaseStatus::Rejected;
        end.message = state->outcome.get().message;
        notify(state->callbacks.not_granted, end);
    }
}

void LeaseScheduler::run(const std::shared_ptr<State>& state, std::stop_token token) {
    struct Finish {
        State& state;
        ~Finish() {
            std::lock_guard lock(state.mutex);
            state.finished = true;
            state.wake.notify_all();
        }
    } finish{*state};
    LeaseGrant grant;
    {
        std::lock_guard lock(state->mutex);
        // A worker freed during shutdown may admit a lease shutdown has not reached
        // yet; leave it ungranted so shutdown reports it cancelled.
        if (state->dropped || shutting_down_) return;
        state->granted = true;
        state->granted_at = Clock::now();
        grant.lease = state->name;
        grant.waited = between(state->requested, state->granted_at);
        grant.reserve_bytes = state->reserve;
    }
    {
        std::lock_guard lock(mutex_);
        ++counters_.granted;
    }
    notify(state->callbacks.granted, grant);

    // Registered before taking the state lock: it may run at once, and it locks.
    std::stop_callback on_stop(token, [state] {
        std::lock_guard lock(state->mutex);
        state->stop_seen = true;
        state->wake.notify_all();
    });
    std::unique_lock lock(state->mutex);
    const auto settled = [&] { return state->released || shutting_down_.load(); };
    state->wake.wait(lock, [&] { return settled() || state->stop_seen || state->reason; });
    if (state->released) return;

    const auto reason = state->reason.value_or(
        shutting_down_ ? StopReason::Shutdown : StopReason::Timeout);
    state->reason = reason;
    lock.unlock();
    notify(events_.stopped, state->name, reason);
    lock.lock();

    // The holder keeps the worker and the reservation until it releases. If it
    // does not release in time, kill the process doing the work so that the
    // budget is not held hostage by a stuck job.
    // Shutdown still tells the holder to stop and gives an attached process its
    // grace period. The global flag must not skip cleanup, but an unattached
    // lease cannot be killed and need not delay shutdown.
    if (options_.kill_grace.count() > 0 && (!shutting_down_ || state->process) &&
        !state->wake.wait_until(lock, detail::deadline_after(options_.kill_grace),
                                [&] { return state->released; }) &&
        state->process) {
        const auto process = *state->process;
        lock.unlock();
        const bool killed = options_.probe->terminate(process);
        if (killed) {
            {
                std::lock_guard counters(mutex_);
                ++counters_.killed;
            }
            notify(events_.killed, state->name, process.pid);
        }
        lock.lock();
        state->killed = state->killed || killed;
    }
    state->wake.wait(lock, settled);
}

void LeaseScheduler::request_stop(const std::shared_ptr<State>& state, StopReason reason) {
    std::shared_ptr<Ticket> ticket;
    {
        std::lock_guard lock(state->mutex);
        if (state->released || state->reason) return;
        state->reason = reason;
        ticket = state->ticket;
        state->wake.notify_all();
    }
    if (ticket) ticket->cancel();
}

AttachResult LeaseScheduler::attach(const std::string& lease, std::uint64_t pid) {
    const auto state = find(lease);
    if (!state) throw std::invalid_argument("unknown lease: " + lease);
    {
        std::lock_guard lock(state->mutex);
        if (!state->granted || state->released)
            throw std::invalid_argument("lease is not running: " + lease);
    }
    const auto process = options_.probe->identify(pid);
    if (!process) return {false, "process not found or not readable", 0};
    const auto resident = options_.probe->resident_bytes(*process);
    if (!resident) return {false, "process resident memory is not readable", 0};
    {
        std::lock_guard lock(state->mutex);
        if (state->reason && state->process && *state->process != *process)
            return {false, "cannot replace process on a stopping lease", 0};
        state->process = process;
    }
    observe_memory(state, *process, *resident);
    return {true, {}, *resident};
}

LeaseEnd LeaseScheduler::release(const std::string& lease) {
    const auto state = find(lease);
    if (!state) throw std::invalid_argument("unknown lease: " + lease);
    {
        std::lock_guard lock(state->mutex);
        if (!state->granted) throw std::invalid_argument("lease has not been granted: " + lease);
        if (state->released) throw std::invalid_argument("lease already released: " + lease);
        state->released = true;
        state->wake.notify_all();
    }
    const auto released_at = Clock::now();
    const Outcome outcome = state->outcome.get();  // the job returns promptly once released
    LeaseEnd end;
    end.lease = lease;
    std::optional<StopReason> reason;
    {
        std::unique_lock lock(state->mutex);
        // Cancellation/deadline outcomes resolve before the executor job exits.
        // Do not acknowledge release while that job may still terminate the
        // attached process: the holder may reuse its process after this returns.
        state->wake.wait(lock, [&] { return state->finished; });
        end.ran = between(state->granted_at, released_at);
        end.peak_resident_bytes = state->peak;
        end.killed = state->killed;
        reason = state->reason;
    }
    if (reason) {
        switch (*reason) {
        case StopReason::Timeout: end.status = LeaseStatus::TimedOut; break;
        case StopReason::Memory: end.status = LeaseStatus::MemoryExceeded; break;
        case StopReason::Cancelled:
        case StopReason::Shutdown: end.status = LeaseStatus::Cancelled; break;
        }
        end.message = std::string("stopped: ") + to_string(*reason);
    } else {
        switch (outcome.status) {
        case Status::Completed: end.status = LeaseStatus::Completed; break;
        case Status::TimedOut: end.status = LeaseStatus::TimedOut; break;
        case Status::Failed: end.status = LeaseStatus::Failed; break;
        case Status::Cancelled: end.status = LeaseStatus::Cancelled; break;
        case Status::Rejected: end.status = LeaseStatus::Rejected; break;
        }
        end.message = outcome.message;
    }
    {
        std::lock_guard lock(mutex_);
        leases_.erase(lease);
    }
    count(end.status);
    return end;
}

bool LeaseScheduler::cancel(const std::string& lease) {
    const auto state = find(lease);
    if (!state) return false;
    std::shared_ptr<Ticket> ticket;
    bool queued = false;
    {
        std::lock_guard lock(state->mutex);
        if (!state->granted) {
            state->dropped = true;
            queued = true;
            ticket = state->ticket;
        }
    }
    if (!queued) {
        request_stop(state, StopReason::Cancelled);
        return true;
    }
    if (ticket) ticket->cancel();
    {
        std::lock_guard lock(mutex_);
        leases_.erase(lease);
    }
    count(LeaseStatus::Cancelled);
    LeaseEnd end;
    end.lease = lease;
    end.status = LeaseStatus::Cancelled;
    end.message = "cancelled before it was granted";
    notify(state->callbacks.not_granted, end);
    return true;
}

void LeaseScheduler::shutdown() {
    if (shutting_down_.exchange(true)) return;
    std::vector<std::shared_ptr<State>> all;
    {
        std::lock_guard lock(mutex_);
        for (const auto& entry : leases_) all.push_back(entry.second);
    }
    for (const auto& state : all) {
        std::shared_ptr<Ticket> ticket;
        bool queued = false;
        {
            std::lock_guard lock(state->mutex);
            if (!state->granted) {
                state->dropped = true;
                queued = true;
                ticket = state->ticket;
            } else if (!state->released && !state->reason) {
                state->reason = StopReason::Shutdown;
            }
            state->wake.notify_all();
        }
        if (queued) {
            if (ticket) ticket->cancel();
            LeaseEnd end;
            end.lease = state->name;
            end.status = LeaseStatus::Cancelled;
            end.message = "scheduler shut down";
            notify(state->callbacks.not_granted, end);
        }
    }
    executor_->shutdown(true);
    {
        std::lock_guard lock(watch_mutex_);
        watch_stop_ = true;
    }
    watch_wake_.notify_all();
    if (watcher_.joinable()) watcher_.join();
    std::lock_guard lock(mutex_);
    leases_.clear();
}

SchedulerStats LeaseScheduler::stats() const {
    SchedulerStats result;
    {
        std::lock_guard lock(mutex_);
        result = counters_;
        for (const auto& entry : leases_) {
            std::lock_guard state(entry.second->mutex);
            if (entry.second->granted && !entry.second->released) ++result.running;
            else if (!entry.second->granted && !entry.second->dropped) ++result.queued;
        }
    }
    result.executor = executor_->stats();
    return result;
}

void LeaseScheduler::observe_memory(const std::shared_ptr<State>& state,
                                    const host::ProcessId& process, std::uint64_t resident) {
    std::shared_ptr<Ticket> ticket;
    {
        std::lock_guard guard(state->mutex);
        // A read started on the previous attachment may finish after reattachment.
        if (state->released || state->process != process) return;
        state->peak = std::max(state->peak, resident);
        if (resident <= state->reserve || state->reason) return;
        state->reason = StopReason::Memory;
        ticket = state->ticket;
        state->wake.notify_all();
    }
    if (ticket) ticket->cancel();
}

void LeaseScheduler::watch_memory(std::vector<Attachment> attached) {
    std::unique_lock lock(watch_mutex_);
    while (!watch_stop_) {
        watch_wake_.wait_until(lock, detail::deadline_after(options_.memory_poll),
                              [&] { return watch_stop_; });
        if (watch_stop_) break;
        lock.unlock();
        {
            std::lock_guard leases(mutex_);
            for (const auto& [name, state] : leases_) {
                std::lock_guard guard(state->mutex);
                if (state->granted && !state->released && !state->reason && state->process)
                    attached.emplace_back(state, *state->process);
            }
        }
        for (const auto& [state, process] : attached) {
            try {
                const auto resident = options_.probe->resident_bytes(process);
                if (resident) observe_memory(state, process, *resident);
            } catch (const std::bad_alloc&) {
                // OS readers can allocate. Retry at the normal interval while
                // preserving this lease's reservation and sampling the others.
            }
        }
        attached.clear();
        lock.lock();
    }
}

} // namespace binaryrat
