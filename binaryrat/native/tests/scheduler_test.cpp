// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/host.hpp>
#include <binaryrat/scheduler.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

using namespace binaryrat;
using namespace std::chrono_literals;

namespace {
[[noreturn]] void fail(const std::string& message) {
    std::cerr << "scheduler test failed: " << message << std::endl;
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

template <class Predicate>
bool eventually(Predicate predicate, std::chrono::milliseconds limit = 10s) {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (!predicate()) {
        if (std::chrono::steady_clock::now() > deadline) return false;
        std::this_thread::sleep_for(1ms);
    }
    return true;
}

// Processes the scheduler may watch, with resident sizes the test controls.
class FakeProbe final : public ProcessProbe {
public:
    void set(std::uint64_t pid, std::uint64_t bytes) {
        std::lock_guard lock(mutex_);
        resident_[pid] = bytes;
    }
    std::vector<std::uint64_t> terminated() {
        std::lock_guard lock(mutex_);
        return terminated_;
    }
    std::optional<host::ProcessId> identify(std::uint64_t pid) override {
        std::lock_guard lock(mutex_);
        if (!resident_.contains(pid)) return std::nullopt;
        return host::ProcessId{pid, 7};
    }
    std::optional<std::uint64_t> resident_bytes(const host::ProcessId& process) override {
        std::lock_guard lock(mutex_);
        const auto found = resident_.find(process.pid);
        if (found == resident_.end()) return std::nullopt;
        return found->second;
    }
    bool terminate(const host::ProcessId& process) override {
        std::lock_guard lock(mutex_);
        terminated_.push_back(process.pid);
        return resident_.erase(process.pid) > 0;
    }

private:
    std::mutex mutex_;
    std::unordered_map<std::uint64_t, std::uint64_t> resident_;
    std::vector<std::uint64_t> terminated_;
};

// Everything the scheduler reports, in arrival order.
class Recorder {
public:
    LeaseCallbacks callbacks() {
        LeaseCallbacks result;
        result.granted = [this](const LeaseGrant& grant) {
            std::lock_guard lock(mutex_);
            granted_.push_back(grant.lease);
        };
        result.not_granted = [this](const LeaseEnd& end) {
            std::lock_guard lock(mutex_);
            refused_.emplace_back(end.lease, end.status);
        };
        return result;
    }
    SchedulerEvents events() {
        SchedulerEvents result;
        result.stopped = [this](const std::string& lease, StopReason reason) {
            std::lock_guard lock(mutex_);
            stops_.emplace_back(lease, reason);
        };
        result.killed = [this](const std::string& lease, std::uint64_t pid) {
            std::lock_guard lock(mutex_);
            kills_.emplace_back(lease, pid);
        };
        return result;
    }
    std::vector<std::string> granted() {
        std::lock_guard lock(mutex_);
        return granted_;
    }
    bool was_granted(const std::string& lease) {
        const auto all = granted();
        return std::find(all.begin(), all.end(), lease) != all.end();
    }
    std::vector<std::pair<std::string, LeaseStatus>> refused() {
        std::lock_guard lock(mutex_);
        return refused_;
    }
    std::vector<std::pair<std::string, StopReason>> stops() {
        std::lock_guard lock(mutex_);
        return stops_;
    }
    std::vector<std::pair<std::string, std::uint64_t>> kills() {
        std::lock_guard lock(mutex_);
        return kills_;
    }

private:
    std::mutex mutex_;
    std::vector<std::string> granted_;
    std::vector<std::pair<std::string, LeaseStatus>> refused_;
    std::vector<std::pair<std::string, StopReason>> stops_;
    std::vector<std::pair<std::string, std::uint64_t>> kills_;
};

// Two CPUs, a 1000-byte pool, 100-byte minimum reservation.
SchedulerOptions options(std::shared_ptr<FakeProbe> probe, std::chrono::milliseconds grace = 0ms) {
    SchedulerOptions result;
    result.budget.cpu_workers = 2;
    result.budget.worker_cap = 8;
    result.budget.ram_bytes = 1000;
    result.budget.worker_bytes = 100;
    result.memory_poll = 2ms;
    result.kill_grace = grace;
    result.probe = std::move(probe);
    return result;
}

LeaseOptions lease(std::uint64_t reserve, std::chrono::milliseconds timeout = 0ms) {
    LeaseOptions result;
    result.reserve_bytes = reserve;
    result.timeout = timeout;
    return result;
}

void cpu_limit_and_fifo_grants() {
    Recorder recorder;
    LeaseScheduler scheduler(options(std::make_shared<FakeProbe>()), recorder.events());
    require(scheduler.workers() == 2, "two CPUs admit two workers");
    for (const auto* name : {"a", "b", "c", "d"}) scheduler.acquire(name, lease(100), recorder.callbacks());
    require(eventually([&] { return recorder.granted().size() == 2; }), "two leases granted");
    std::this_thread::sleep_for(20ms);
    require(recorder.granted().size() == 2, "a third lease waits for a CPU");
    require(scheduler.stats().queued == 2 && scheduler.stats().running == 2, "stats show the queue");
    const auto end = scheduler.release("a");
    require(end.status == LeaseStatus::Completed, "a released lease completes");
    require(eventually([&] { return recorder.granted().size() == 3; }), "release admits the next lease");
    require(recorder.granted()[2] == "c", "admission is first in, first out");
    scheduler.release("b");
    scheduler.release("c");
    require(eventually([&] { return recorder.was_granted("d"); }), "the last lease runs");
    scheduler.release("d");
    require(scheduler.stats().completed == 4, "four completions counted");
}

void memory_reservations_limit_admission() {
    Recorder recorder;
    LeaseScheduler scheduler(options(std::make_shared<FakeProbe>()), recorder.events());
    scheduler.acquire("big", lease(700), recorder.callbacks());
    scheduler.acquire("next", lease(400), recorder.callbacks());
    require(eventually([&] { return recorder.was_granted("big"); }), "big lease granted");
    std::this_thread::sleep_for(20ms);
    require(!recorder.was_granted("next"), "700 + 400 bytes do not fit a 1000-byte pool");
    scheduler.release("big");
    require(eventually([&] { return recorder.was_granted("next"); }), "freed memory admits the next lease");
    scheduler.release("next");

    scheduler.acquire("huge", lease(1001), recorder.callbacks());
    const auto refused = recorder.refused();
    require(refused.size() == 1 && refused[0].first == "huge" &&
            refused[0].second == LeaseStatus::Rejected,
            "a lease larger than the pool is rejected before acquire returns");
    requires_throw<std::invalid_argument>([&] { scheduler.release("huge"); },
                                          "a rejected lease is gone");
}

void deadline_stops_the_holder() {
    Recorder recorder;
    LeaseScheduler scheduler(options(std::make_shared<FakeProbe>()), recorder.events());
    scheduler.acquire("slow", lease(100, 30ms), recorder.callbacks());
    require(eventually([&] { return !recorder.stops().empty(); }), "the deadline stops the lease");
    require(recorder.stops()[0] == std::make_pair(std::string("slow"), StopReason::Timeout),
            "the stop names the deadline");
    const auto end = scheduler.release("slow");
    require(end.status == LeaseStatus::TimedOut, "a stopped lease reports its timeout");
    require(end.ran >= 30ms, "the run time covers the deadline");
    require(!end.killed, "no process was killed");
}

void cancelling_running_and_queued_leases() {
    Recorder recorder;
    LeaseScheduler scheduler(options(std::make_shared<FakeProbe>()), recorder.events());
    scheduler.acquire("one", lease(100), recorder.callbacks());
    scheduler.acquire("two", lease(100), recorder.callbacks());
    scheduler.acquire("three", lease(100), recorder.callbacks());
    require(eventually([&] { return recorder.granted().size() == 2; }), "two running");
    require(scheduler.cancel("three"), "a queued lease can be cancelled");
    const auto refused = recorder.refused();
    require(refused.size() == 1 && refused[0] == std::make_pair(std::string("three"), LeaseStatus::Cancelled),
            "a cancelled queued lease is reported as never granted");
    require(scheduler.cancel("one"), "a running lease can be cancelled");
    require(eventually([&] { return recorder.stops().size() == 1; }), "the holder is told to stop");
    require(recorder.stops()[0].second == StopReason::Cancelled, "the stop names the cancel");
    require(scheduler.release("one").status == LeaseStatus::Cancelled, "release reports the cancel");
    require(!scheduler.cancel("missing"), "an unknown lease cannot be cancelled");
    std::this_thread::sleep_for(20ms);
    require(!recorder.was_granted("three"), "a cancelled queued lease never runs");
    scheduler.release("two");
}

void attached_process_over_its_reservation_is_stopped() {
    auto probe = std::make_shared<FakeProbe>();
    probe->set(42, 50);
    Recorder recorder;
    LeaseScheduler scheduler(options(probe), recorder.events());
    scheduler.acquire("job", lease(300), recorder.callbacks());
    require(eventually([&] { return recorder.was_granted("job"); }), "granted");
    const auto attached = scheduler.attach("job", 42);
    require(attached.attached && attached.resident_bytes == 50, "attach reads resident memory");
    std::this_thread::sleep_for(20ms);
    require(recorder.stops().empty(), "within the reservation nothing happens");
    probe->set(42, 301);
    require(eventually([&] { return recorder.stops().size() == 1; }), "growth past the reservation stops the lease");
    require(recorder.stops()[0].second == StopReason::Memory, "the stop names memory");
    const auto end = scheduler.release("job");
    require(end.status == LeaseStatus::MemoryExceeded, "release reports the memory overrun");
    require(end.peak_resident_bytes == 301, "peak resident memory is reported");

    {
        // A watcher that never polls in time: only attach() itself can catch this.
        auto slow = options(probe);
        slow.memory_poll = std::chrono::hours(1);
        Recorder attached_recorder;
        LeaseScheduler attaching(slow, attached_recorder.events());
        attaching.acquire("already", lease(100), attached_recorder.callbacks());
        require(eventually([&] { return attached_recorder.was_granted("already"); }), "granted");
        probe->set(43, 5000);
        require(attaching.attach("already", 43).attached, "attached");
        require(eventually([&] { return attached_recorder.stops().size() == 1; }),
                "attaching an oversized process stops the lease without waiting for the watcher");
        require(attaching.release("already").status == LeaseStatus::MemoryExceeded, "memory overrun");
    }

    scheduler.acquire("ghost", lease(100), recorder.callbacks());
    require(eventually([&] { return recorder.was_granted("ghost"); }), "granted");
    const auto missing = scheduler.attach("ghost", 999);
    require(!missing.attached && !missing.reason.empty(), "an unknown PID is not attached");
    scheduler.release("ghost");
}

void holder_that_ignores_a_stop_has_its_process_killed() {
    auto probe = std::make_shared<FakeProbe>();
    probe->set(77, 10);
    Recorder recorder;
    LeaseScheduler scheduler(options(probe, 40ms), recorder.events());
    scheduler.acquire("stuck", lease(100), recorder.callbacks());
    require(eventually([&] { return recorder.was_granted("stuck"); }), "granted");
    require(scheduler.attach("stuck", 77).attached, "attached");
    scheduler.cancel("stuck");
    require(eventually([&] { return recorder.stops().size() == 1; }), "the holder is told to stop");
    std::this_thread::sleep_for(10ms);
    require(recorder.kills().empty(), "nothing is killed inside the grace period");
    require(eventually([&] { return recorder.kills().size() == 1; }), "the attached process is killed after the grace period");
    require(recorder.kills()[0] == std::make_pair(std::string("stuck"), std::uint64_t{77}), "the kill names the PID");
    require(probe->terminated() == std::vector<std::uint64_t>{77}, "exactly that process was terminated");
    const auto end = scheduler.release("stuck");
    require(end.status == LeaseStatus::Cancelled && end.killed, "release reports the kill");
    require(scheduler.stats().killed == 1, "kills are counted");
}

void release_waits_for_in_flight_process_termination() {
    class BlockingProbe final : public ProcessProbe {
    public:
        std::promise<void> terminating;
        std::promise<void> allow_termination;
        std::shared_future<void> allowed = allow_termination.get_future().share();
        std::optional<host::ProcessId> identify(std::uint64_t pid) override {
            return host::ProcessId{pid, 1};
        }
        std::optional<std::uint64_t> resident_bytes(const host::ProcessId&) override {
            return 10;
        }
        bool terminate(const host::ProcessId&) override {
            terminating.set_value();
            allowed.wait();
            return true;
        }
    };
    auto probe = std::make_shared<BlockingProbe>();
    auto config = options(std::make_shared<FakeProbe>(), 10ms);
    config.probe = probe;
    Recorder recorder;
    LeaseScheduler scheduler(config, recorder.events());
    scheduler.acquire("stuck", lease(100), recorder.callbacks());
    require(eventually([&] { return recorder.was_granted("stuck"); }), "lease granted");
    require(scheduler.attach("stuck", 77).attached, "process attached");
    scheduler.cancel("stuck");
    require(probe->terminating.get_future().wait_for(10s) == std::future_status::ready,
            "process termination has started");
    std::promise<void> releasing;
    auto end = std::async(std::launch::async, [&] {
        releasing.set_value();
        return scheduler.release("stuck");
    });
    releasing.get_future().wait();
    const bool waited = end.wait_for(50ms) == std::future_status::timeout;
    probe->allow_termination.set_value();
    require(waited, "release must not acknowledge while its process termination is in flight");
    require(end.wait_for(10s) == std::future_status::ready, "release finishes after termination");
    const auto result = end.get();
    require(result.status == LeaseStatus::Cancelled && result.killed,
            "release reports the completed termination result");
    require(scheduler.stats().killed == 1, "termination is counted exactly once");
}

void prompt_release_or_zero_grace_kills_nothing() {
    auto probe = std::make_shared<FakeProbe>();
    probe->set(5, 10);
    Recorder recorder;
    {
        LeaseScheduler scheduler(options(probe, 200ms), recorder.events());
        scheduler.acquire("polite", lease(100), recorder.callbacks());
        require(eventually([&] { return recorder.was_granted("polite"); }), "granted");
        require(scheduler.attach("polite", 5).attached, "attached");
        scheduler.cancel("polite");
        require(eventually([&] { return recorder.stops().size() == 1; }), "stopped");
        require(!scheduler.release("polite").killed, "a prompt release is not killed");
    }
    {
        LeaseScheduler scheduler(options(probe, 0ms), recorder.events());
        scheduler.acquire("patient", lease(100), recorder.callbacks());
        require(eventually([&] { return recorder.was_granted("patient"); }), "granted");
        require(scheduler.attach("patient", 5).attached, "attached");
        scheduler.cancel("patient");
        require(eventually([&] { return recorder.stops().size() == 2; }), "stopped");
        std::this_thread::sleep_for(60ms);
        require(!scheduler.release("patient").killed, "zero grace never kills");
    }
    require(probe->terminated().empty(), "nothing was terminated");
}

void misuse_is_reported() {
    Recorder recorder;
    LeaseScheduler scheduler(options(std::make_shared<FakeProbe>()), recorder.events());
    requires_throw<std::invalid_argument>([&] { scheduler.acquire("", lease(100), recorder.callbacks()); },
                                          "empty name");
    requires_throw<std::invalid_argument>(
        [&] { scheduler.acquire("t", lease(100, -1ms), recorder.callbacks()); }, "negative timeout");
    scheduler.acquire("x", lease(100), recorder.callbacks());
    scheduler.acquire("y", lease(100), recorder.callbacks());
    scheduler.acquire("z", lease(100), recorder.callbacks());
    requires_throw<std::invalid_argument>([&] { scheduler.acquire("x", lease(100), recorder.callbacks()); },
                                          "duplicate name");
    require(eventually([&] { return recorder.granted().size() == 2; }), "two running");
    requires_throw<std::invalid_argument>([&] { scheduler.release("z"); }, "release of a queued lease");
    requires_throw<std::invalid_argument>([&] { scheduler.attach("z", 1); }, "attach to a queued lease");
    requires_throw<std::invalid_argument>([&] { scheduler.release("nope"); }, "release of an unknown lease");
    scheduler.release("x");
    requires_throw<std::invalid_argument>([&] { scheduler.release("x"); }, "double release");
    scheduler.release("y");
    require(eventually([&] { return recorder.was_granted("z"); }), "z runs");
    scheduler.release("z");

    SchedulerOptions bad = options(std::make_shared<FakeProbe>());
    bad.max_pending = 0;
    requires_throw<std::invalid_argument>([&] { LeaseScheduler s(bad, {}); }, "zero queue");
    bad = options(std::make_shared<FakeProbe>());
    bad.budget.ram_bytes = 50;
    requires_throw<ResourceExhausted>([&] { LeaseScheduler s(bad, {}); }, "budget without one worker");
}

void full_queue_is_refused_without_blocking() {
    Recorder recorder;
    auto opts = options(std::make_shared<FakeProbe>());
    opts.budget.cpu_workers = 1;
    opts.max_pending = 2;
    LeaseScheduler scheduler(opts, recorder.events());
    scheduler.acquire("run", lease(100), recorder.callbacks());
    require(eventually([&] { return recorder.was_granted("run"); }), "running");
    scheduler.acquire("q1", lease(100), recorder.callbacks());
    scheduler.acquire("q2", lease(100), recorder.callbacks());
    requires_throw<std::invalid_argument>([&] { scheduler.acquire("q3", lease(100), recorder.callbacks()); },
                                          "a full queue refuses instead of blocking");
    scheduler.release("run");
    require(eventually([&] { return recorder.was_granted("q1"); }), "q1 runs");
    scheduler.release("q1");
    require(eventually([&] { return recorder.was_granted("q2"); }), "q2 runs");
    scheduler.release("q2");
}

void shutdown_cancels_queued_and_unblocks_running() {
    Recorder recorder;
    auto opts = options(std::make_shared<FakeProbe>());
    opts.budget.cpu_workers = 1;
    LeaseScheduler scheduler(opts, recorder.events());
    scheduler.acquire("running", lease(100), recorder.callbacks());
    scheduler.acquire("waiting", lease(100), recorder.callbacks());
    require(eventually([&] { return recorder.was_granted("running"); }), "running");
    scheduler.shutdown();
    const auto refused = recorder.refused();
    require(refused.size() == 1 && refused[0] == std::make_pair(std::string("waiting"), LeaseStatus::Cancelled),
            "shutdown reports queued leases as cancelled");
    requires_throw<std::logic_error>([&] { scheduler.acquire("late", lease(100), recorder.callbacks()); },
                                     "no leases after shutdown");
    scheduler.shutdown();
}

void shutdown_notifies_and_cleans_attached_processes() {
    for (const auto grace : {0ms, 10ms}) {
        auto probe = std::make_shared<FakeProbe>();
        probe->set(88, 10);
        Recorder recorder;
        auto config = options(probe, grace);
        config.budget.cpu_workers = 1;
        LeaseScheduler scheduler(config, recorder.events());
        scheduler.acquire("running", lease(100), recorder.callbacks());
        require(eventually([&] { return recorder.was_granted("running"); }), "lease running");
        require(scheduler.attach("running", 88).attached, "process attached");
        scheduler.acquire("queued", lease(100), recorder.callbacks());
        auto stopped = std::async(std::launch::async, [&] { scheduler.shutdown(); });
        require(stopped.wait_for(2s) == std::future_status::ready,
                "shutdown must finish without a holder releasing its lease");
        stopped.get();
        require(recorder.stops() == std::vector<std::pair<std::string, StopReason>>{
                    {"running", StopReason::Shutdown}},
                "shutdown must notify a running holder exactly once");
        const auto refused = recorder.refused();
        require(refused.size() == 1 && refused[0] ==
                    std::make_pair(std::string("queued"), LeaseStatus::Cancelled),
                "shutdown must cancel its queued lease");
        if (grace.count() == 0) {
            require(probe->terminated().empty() && recorder.kills().empty(),
                    "zero-grace shutdown must not terminate an attached process");
        } else {
            require(probe->terminated() == std::vector<std::uint64_t>{88},
                    "shutdown must terminate only the attached process after its grace period");
            require(recorder.kills().size() == 1, "shutdown must report completed process cleanup");
        }
        require(scheduler.stats().executor.reserved_bytes == 0,
                "shutdown must release admission reservations after cleanup");
    }
}

// Shutdown visits leases in hash-map order, which differs between standard
// libraries. A running lease visited first frees its worker while queued leases
// are still unvisited; none of them may be granted after shutdown has begun.
void shutdown_never_grants_queued_leases() {
    constexpr int queued = 40;
    for (int round = 0; round < 20; ++round) {
        Recorder recorder;
        auto opts = options(std::make_shared<FakeProbe>());
        opts.budget.cpu_workers = 1;
        opts.max_pending = queued;
        LeaseScheduler scheduler(opts, recorder.events());
        scheduler.acquire("running", lease(100), recorder.callbacks());
        require(eventually([&] { return recorder.was_granted("running"); }), "running");
        for (int i = 0; i < queued; ++i)
            scheduler.acquire("queued-" + std::to_string(i), lease(100), recorder.callbacks());
        scheduler.shutdown();
        require(recorder.granted().size() == 1, "shutdown grants no queued lease");
        const auto refused = recorder.refused();
        require(refused.size() == queued &&
                    std::all_of(refused.begin(), refused.end(),
                                [](const auto& end) { return end.second == LeaseStatus::Cancelled; }),
                "every queued lease is reported cancelled");
    }
}

void host_probe_reads_this_process_and_refuses_stale_identities() {
    const auto machine = host::machine();
    require(machine.logical_cpus >= 1, "at least one CPU");
    if (!host::process_queries_supported()) return;
    require(machine.physical_memory_bytes > 0, "physical memory is known");
#ifdef _WIN32
    const auto self = static_cast<std::uint64_t>(_getpid());
#else
    const auto self = static_cast<std::uint64_t>(getpid());
#endif
    const auto identity = host::identify(self);
    require(identity.has_value() && identity->pid == self, "this process can be identified");
    const auto resident = host::resident_bytes(*identity);
    require(resident.has_value() && *resident > 0, "this process has resident memory");
    require(host::identify(self) == identity, "identity is stable");
    host::ProcessId stale = *identity;
    stale.start_stamp += 1;
    require(!host::resident_bytes(stale).has_value(), "a PID with another start time is not read");
    require(!host::terminate(stale), "a PID with another start time is never killed");
    require(!host::identify(0).has_value(), "PID 0 is not identified");
}

} // namespace

int main() {
    // Backstop: a lost wakeup would otherwise hang the test run.
    std::thread([] {
        std::this_thread::sleep_for(120s);
        fail("timed out");
    }).detach();
    cpu_limit_and_fifo_grants();
    memory_reservations_limit_admission();
    deadline_stops_the_holder();
    cancelling_running_and_queued_leases();
    attached_process_over_its_reservation_is_stopped();
    holder_that_ignores_a_stop_has_its_process_killed();
    release_waits_for_in_flight_process_termination();
    prompt_release_or_zero_grace_kills_nothing();
    misuse_is_reported();
    full_queue_is_refused_without_blocking();
    shutdown_cancels_queued_and_unblocks_running();
    shutdown_notifies_and_cleans_attached_processes();
    shutdown_never_grants_queued_leases();
    host_probe_reads_this_process_and_refuses_stale_identities();
    std::cout << "scheduler tests passed" << std::endl;
    return 0;
}
