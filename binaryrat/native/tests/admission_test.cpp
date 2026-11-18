// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/admission.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace binaryrat;
using namespace std::chrono_literals;

namespace {
// A failed check reports and exits at once instead of throwing. Unwinding would
// destroy an executor whose jobs are still blocked on a gate, and that destructor
// waits for them forever, turning a clear failure into a hang.
[[noreturn]] void fail(const char* message) {
    std::cerr << "admission test failed: " << message << std::endl;
    std::_Exit(1);
}

void require(bool condition, const char* message) {
    if (!condition) fail(message);
}

template <class Exception, class Action>
void requires_throw(Action action) {
    try { action(); }
    catch (const Exception&) { return; }
    fail("expected exception was not thrown");
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

bool ready(std::future<Outcome>& result, std::chrono::milliseconds limit = 10s) {
    return result.wait_for(limit) == std::future_status::ready;
}

Budget budget(std::size_t cpu, std::size_t cap, std::uint64_t ram, std::uint64_t jvm,
              std::uint64_t other, std::uint64_t worker) {
    Budget b;
    b.cpu_workers = cpu;
    b.worker_cap = cap;
    b.ram_bytes = ram;
    b.jvm_reserve_bytes = jvm;
    b.other_reserve_bytes = other;
    b.worker_bytes = worker;
    return b;
}

// Four workers, 1000-byte pool, 100-byte worker baseline.
Budget small_budget() { return budget(4, 4, 1000, 0, 0, 100); }

// A job that signals it started, then waits for the shared release flag. It
// ignores its stop token on purpose: the executor must stay inside its budget
// even for jobs that do not cooperate.
struct Gate {
    std::atomic<int> started{0};
    std::promise<void> release;
    std::shared_future<void> released = release.get_future().share();
    std::function<void(std::stop_token)> job() {
        return [this](std::stop_token) {
            started.fetch_add(1);
            released.wait();
        };
    }
};

void worker_limit_formula() {
    constexpr auto max = std::numeric_limits<std::uint64_t>::max();
    // RAM-bound: (10000 - 2000 - 1000) / 1000 = 7 < cpu 8 < cap 16.
    require(worker_limit(budget(8, 16, 10000, 2000, 1000, 1000)) == 7, "RAM must bound workers");
    require(worker_limit(budget(2, 16, 10000, 2000, 1000, 1000)) == 2, "CPU must bound workers");
    require(worker_limit(budget(8, 3, 10000, 2000, 1000, 1000)) == 3, "cap must bound workers");
    // Exact boundary: 2000 / 1000 = 2, but one byte less leaves only one worker.
    require(worker_limit(budget(8, 8, 3000, 1000, 0, 1000)) == 2, "exact fit admits two workers");
    require(worker_limit(budget(8, 8, 2999, 1000, 0, 1000)) == 1, "one byte short loses a worker");
    // Reserves at or beyond RAM leave nothing; they must not underflow.
    require(worker_limit(budget(8, 8, 1000, 600, 400, 100)) == 0, "reserves equal to RAM leave zero");
    require(worker_limit(budget(8, 8, 1000, 900, 900, 100)) == 0, "reserves above RAM leave zero");
    require(native_pool_bytes(budget(8, 8, 1000, 900, 900, 100)) == 0, "pool saturates at zero");
    require(native_pool_bytes(budget(8, 8, 5000, max, max, 100)) == 0, "huge reserves must not overflow");
    require(native_pool_bytes(budget(8, 8, 5000, 1000, 500, 100)) == 3500, "pool is RAM minus reserves");
    require(worker_limit(budget(8, 99, max, 0, 0, 1)) == 8, "huge RAM leaves CPU as the bound");
    requires_throw<std::invalid_argument>([] { (void) worker_limit(budget(0, 4, 1000, 0, 0, 100)); });
    requires_throw<std::invalid_argument>([] { (void) worker_limit(budget(4, 0, 1000, 0, 0, 100)); });
    requires_throw<std::invalid_argument>([] { (void) worker_limit(budget(4, 4, 1000, 0, 0, 0)); });
    // Constructor: a budget that cannot hold one worker is refused, never forced.
    requires_throw<ResourceExhausted>([] { AdmissionExecutor e(budget(4, 4, 1000, 950, 0, 100), 1); });
    requires_throw<std::invalid_argument>([] { AdmissionExecutor e(small_budget(), 0); });
    AdmissionExecutor ok(budget(8, 16, 10000, 2000, 1000, 1000), 4);
    require(ok.stats().workers == 7, "executor must use the computed worker limit");
    require(ok.stats().pool_bytes == 7000, "executor must expose the native pool size");
}

void memory_admission_limits_concurrency() {
    // Two 400-byte tasks fit in 1000 bytes; a third (1200) must wait.
    {
        AdmissionExecutor pool(small_budget(), 8);
        Gate gate;
        std::vector<Ticket> tickets;
        for (int i = 0; i < 4; ++i) tickets.push_back(pool.submit({400, 0ms}, gate.job()));
        require(eventually([&] { return gate.started.load() == 2; }), "two tasks must start");
        std::this_thread::sleep_for(100ms);
        require(gate.started.load() == 2, "memory must hold back the third task");
        const auto held = pool.stats();
        require(held.running == 2 && held.reserved_bytes == 800 && held.queued == 2,
                "stats must show two running, 800 bytes reserved, two queued");
        gate.release.set_value();
        for (auto& t : tickets) {
            require(ready(t.result) && t.result.get().status == Status::Completed, "task must complete");
        }
        const auto done = pool.stats();
        require(done.peak_reserved_bytes == 800 && done.peak_running == 2, "peaks must match the limit");
        require(done.reserved_bytes == 0 && done.running == 0, "reservations must be released");
    }
    // Control: with the default 100-byte reservation all four workers run at once.
    {
        AdmissionExecutor pool(small_budget(), 8);
        Gate gate;
        std::vector<Ticket> tickets;
        for (int i = 0; i < 4; ++i) tickets.push_back(pool.submit({0, 0ms}, gate.job()));
        require(eventually([&] { return gate.started.load() == 4; }), "all four small tasks must start");
        require(pool.stats().reserved_bytes == 400, "a zero request is raised to worker_bytes");
        gate.release.set_value();
        for (auto& t : tickets) require(ready(t.result) && t.result.get().status == Status::Completed, "complete");
    }
}

void reservation_addition_must_not_wrap() {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    constexpr auto reservation = maximum / 2 + 1;
    AdmissionExecutor pool(budget(2, 2, maximum, 0, 0, 1), 2);
    Gate gate;
    auto first = pool.submit({reservation, 0ms}, gate.job());
    require(eventually([&] { return gate.started.load() == 1; }), "first large task must start");
    auto second = pool.submit({reservation, 0ms}, gate.job());
    std::this_thread::sleep_for(100ms);
    const auto held = pool.stats();
    require(gate.started.load() == 1 && held.running == 1 && held.queued == 1,
            "two large reservations must not be admitted through unsigned wraparound");
    require(held.reserved_bytes == reservation && held.peak_reserved_bytes == reservation,
            "large reservation accounting must remain exact");
    gate.release.set_value();
    for (auto* ticket : {&first, &second}) {
        require(ready(ticket->result) && ticket->result.get().status == Status::Completed,
                "large reservations must drain in turn");
    }
    require(pool.stats().reserved_bytes == 0, "large reservations must be returned");
}

void strict_fifo_admission() {
    AdmissionExecutor pool(small_budget(), 8);
    Gate gate_a;
    std::atomic<int> sequence{0}, b_order{0}, c_order{0};
    std::promise<void> release_rest;
    auto rest = release_rest.get_future().share();
    auto a = pool.submit({600, 0ms}, gate_a.job());
    require(eventually([&] { return gate_a.started.load() == 1; }), "A must start");
    auto b = pool.submit({950, 0ms}, [&](std::stop_token) { b_order = ++sequence; rest.wait(); });
    auto c = pool.submit({100, 0ms}, [&](std::stop_token) { c_order = ++sequence; rest.wait(); });
    // C would fit beside A (700 <= 1000) but B is ahead of it and does not (1550).
    std::this_thread::sleep_for(100ms);
    require(b_order.load() == 0 && c_order.load() == 0, "neither B nor C may start while A holds 600");
    require(pool.stats().queued == 2, "B and C must stay queued");
    gate_a.release.set_value();
    // B (950) fits once A is gone; C (100) cannot fit beside B (1050), so C can only
    // start after B finishes. That makes the order independent of thread scheduling.
    require(eventually([&] { return b_order.load() != 0; }), "B must start once A releases");
    std::this_thread::sleep_for(100ms);
    require(c_order.load() == 0, "C must wait for B's memory: 950 + 100 exceeds the pool");
    release_rest.set_value();
    require(eventually([&] { return c_order.load() != 0; }), "C must start after B finishes");
    require(b_order.load() < c_order.load(), "admission must be FIFO: B before C");
    for (auto* t : {&a, &b, &c}) require(ready(t->result) && t->result.get().status == Status::Completed, "complete");
}

void rejection() {
    AdmissionExecutor pool(small_budget(), 2);
    std::atomic<bool> ran{false};
    auto big = pool.submit({1001, 0ms}, [&](std::stop_token) { ran = true; });
    require(ready(big.result, 1s), "an impossible reservation must resolve at once");
    const auto outcome = big.result.get();
    require(outcome.status == Status::Rejected, "reservation over the pool must be rejected");
    require(outcome.message.find("budget") != std::string::npos, "rejection must name the budget");
    require(pool.stats().queued == 0 && !ran.load(), "a rejected task must never queue or run");
    // Exactly the pool size is admitted.
    auto exact = pool.submit({1000, 0ms}, [](std::stop_token) {});
    require(ready(exact.result) && exact.result.get().status == Status::Completed, "pool-sized task must run");
    pool.shutdown();
    auto late = pool.submit({0, 0ms}, [&](std::stop_token) { ran = true; });
    require(ready(late.result, 1s) && late.result.get().status == Status::Rejected, "post-shutdown must reject");
    require(!ran.load(), "a task submitted after shutdown must not run");
    requires_throw<std::invalid_argument>([&] { (void) pool.submit({0, 0ms}, {}); });
    requires_throw<std::invalid_argument>([&] { (void) pool.submit({0, -1ms}, [](std::stop_token) {}); });
}

void bounded_backpressure() {
    AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 1);
    Gate gate;
    auto first = pool.submit({0, 0ms}, gate.job());
    require(eventually([&] { return gate.started.load() == 1; }), "first task must start");
    auto second = pool.submit({0, 0ms}, [](std::stop_token) {});
    std::promise<void> submitting;
    auto producer = std::async(std::launch::async, [&] {
        submitting.set_value();
        return pool.submit({0, 0ms}, [](std::stop_token) {});
    });
    submitting.get_future().wait();
    const bool blocked = producer.wait_for(100ms) == std::future_status::timeout;
    gate.release.set_value();
    require(blocked, "submit must block while the pending queue is full");
    auto third = producer.get();
    for (auto* t : {&first, &second, &third}) require(ready(t->result) && t->result.get().status == Status::Completed, "complete");
}

void timeouts() {
    // A job that ignores its token: the outcome still resolves at the deadline,
    // but the worker and the reservation stay held until the job returns.
    {
        AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 2);
        Gate gate;
        const auto began = std::chrono::steady_clock::now();
        auto ticket = pool.submit({300, 50ms}, gate.job());
        require(ready(ticket.result), "a timed-out task must resolve");
        require(std::chrono::steady_clock::now() - began >= 45ms, "must not resolve before the deadline");
        require(ticket.result.get().status == Status::TimedOut, "status must be TimedOut");
        const auto stats = pool.stats();
        require(stats.running == 1 && stats.reserved_bytes == 300, "an uncooperative job keeps its reservation");
        gate.release.set_value();
        require(eventually([&] { return pool.stats().running == 0 && pool.stats().reserved_bytes == 0; }),
                "capacity must return once the job exits");
    }
    // A cooperative job observes the stop token and exits promptly.
    {
        AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 2);
        std::atomic<bool> saw_stop{false};
        auto ticket = pool.submit({0, 50ms}, [&](std::stop_token token) {
            while (!token.stop_requested()) std::this_thread::sleep_for(1ms);
            saw_stop = true;
        });
        require(ready(ticket.result) && ticket.result.get().status == Status::TimedOut, "must time out");
        require(eventually([&] { return saw_stop.load() && pool.stats().running == 0; }), "job must see the stop");
    }
    // Control: a job that finishes inside its deadline is Completed, and its
    // deadline entry is gone, so the later deadline cannot flip the status.
    {
        AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 2);
        auto ticket = pool.submit({0, 100ms}, [](std::stop_token) {});
        require(ready(ticket.result) && ticket.result.get().status == Status::Completed, "must complete");
        std::this_thread::sleep_for(200ms);
    }
    // The deadline counts from job start: time spent queued does not consume it.
    {
        AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 2);
        auto blocker = pool.submit({0, 0ms}, [](std::stop_token) { std::this_thread::sleep_for(300ms); });
        auto quick = pool.submit({0, 100ms}, [](std::stop_token) {});
        require(ready(quick.result) && quick.result.get().status == Status::Completed,
                "queue wait must not count against the execution deadline");
        require(ready(blocker.result) && blocker.result.get().status == Status::Completed, "blocker completes");
    }
    // A valid positive millisecond count can exceed steady_clock's range.
    // Saturate it rather than overflowing during conversion or addition.
    for (const auto timeout : {
            std::chrono::milliseconds::max(),
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::duration::max())}) {
        AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 2);
        Gate gate;
        auto ticket = pool.submit({0, timeout}, gate.job());
        require(eventually([&] { return gate.started.load() == 1; }), "long-deadline task must start");
        require(ticket.result.wait_for(100ms) == std::future_status::timeout,
                "an enormous positive timeout must not wrap to an expired deadline");
        gate.release.set_value();
        require(ready(ticket.result) && ticket.result.get().status == Status::Completed,
                "long-deadline task must complete normally");
    }
}

void stop_callbacks_run_without_executor_locks() {
    for (const bool cancel : {false, true}) {
        AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 2);
        std::promise<void> registered, callback_finished, release;
        auto released = release.get_future().share();
        auto registered_result = registered.get_future();
        auto callback_result = callback_finished.get_future();
        std::atomic<bool> saw_reservation{false}, rejected_submit{false}, rejected_shutdown{false};
        auto ticket = pool.submit({300, cancel ? 0ms : 250ms}, [&](std::stop_token token) {
            std::stop_callback callback(token, [&] {
                // stats() takes the executor mutex. This must work from both
                // the watchdog thread and a caller performing cancellation.
                const auto stats = pool.stats();
                saw_reservation = stats.running == 1 && stats.reserved_bytes == 300;
                try { (void) pool.submit({0, 0ms}, [](std::stop_token) {}); }
                catch (const std::logic_error&) { rejected_submit = true; }
                try { pool.shutdown(); }
                catch (const std::logic_error&) { rejected_shutdown = true; }
                callback_finished.set_value();
            });
            registered.set_value();
            released.wait();
        });
        require(registered_result.wait_for(10s) == std::future_status::ready,
                "task must register its stop callback");
        std::future<void> canceller;
        if (cancel) {
            canceller = std::async(std::launch::async, [&] { ticket.cancel(); });
        }
        require(ready(ticket.result), "stop outcome must resolve");
        require(ticket.result.get().status == (cancel ? Status::Cancelled : Status::TimedOut),
                "stop callback must preserve the winning outcome");
        require(callback_result.wait_for(10s) == std::future_status::ready,
                "stop callback must finish without an executor-lock deadlock");
        require(saw_reservation.load(), "a stopped but running job retains its reservation");
        require(rejected_submit.load() && rejected_shutdown.load(),
                "stop callbacks must reject recursive submit and shutdown");
        if (cancel) canceller.get();
        release.set_value();
        pool.shutdown();
        require(pool.stats().reserved_bytes == 0 && pool.stats().running == 0,
                "callback completion must not leak capacity");
    }
}

void delayed_watchdog_does_not_hide_expired_completion() {
    AdmissionExecutor pool(budget(2, 2, 1000, 0, 0, 100), 4);
    std::promise<void> callback_entered, release_callback;
    auto callback_entered_result = callback_entered.get_future();
    auto callback_released = release_callback.get_future().share();
    auto first = pool.submit({100, 250ms}, [&](std::stop_token token) {
        std::stop_callback callback(token, [&] {
            callback_entered.set_value();
            callback_released.wait();
        });
        while (!token.stop_requested()) std::this_thread::yield();
    });
    require(callback_entered_result.wait_for(10s) == std::future_status::ready,
            "the first timeout callback must start");

    // Keep the watchdog in the first callback until the second job has actually
    // returned. The second worker must enforce its own elapsed deadline.
    std::promise<std::stop_token> second_started;
    auto second_started_result = second_started.get_future();
    std::promise<void> release_second;
    auto second_released = release_second.get_future().share();
    auto second = pool.submit({100, 10ms}, [&](std::stop_token token) {
        second_started.set_value(token);
        second_released.wait();
    });
    require(second_started_result.wait_for(10s) == std::future_status::ready,
            "the second job must start while the watchdog is occupied");
    const auto token = second_started_result.get();
    std::this_thread::sleep_for(50ms);
    release_second.set_value();
    require(ready(second.result), "an expired job must resolve even with a delayed watchdog");
    require(second.result.get().status == Status::TimedOut,
            "completion after the deadline must be TimedOut, not Completed");
    require(eventually([&] { return token.stop_requested(); }),
            "a worker-detected timeout must request the stop token");
    release_callback.set_value();
    pool.shutdown();
    require(ready(first.result) && first.result.get().status == Status::TimedOut,
            "the first job must keep its timeout outcome");
    require(pool.stats().reserved_bytes == 0 && pool.stats().running == 0,
            "delayed timeout delivery must not leak reservations");
}

void cancellation() {
    AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 4);
    Gate gate;
    auto blocker = pool.submit({0, 0ms}, gate.job());
    require(eventually([&] { return gate.started.load() == 1; }), "blocker must start");
    // Queued task: removed at once, never runs, queue slot freed.
    std::atomic<bool> ran{false};
    auto queued = pool.submit({0, 0ms}, [&](std::stop_token) { ran = true; });
    require(pool.stats().queued == 1, "task must be queued behind the blocker");
    queued.cancel();
    queued.cancel();  // idempotent
    require(ready(queued.result, 1s) && queued.result.get().status == Status::Cancelled, "queued cancel");
    require(pool.stats().queued == 0, "cancel must free the queue slot");
    gate.release.set_value();
    require(ready(blocker.result) && blocker.result.get().status == Status::Completed, "blocker completes");
    require(!ran.load(), "a cancelled queued task must never run");
    // Running task: stop requested, outcome resolves at once, job exits cooperatively.
    std::atomic<bool> saw_stop{false}, running{false};
    auto active = pool.submit({0, 0ms}, [&](std::stop_token token) {
        running = true;
        while (!token.stop_requested()) std::this_thread::sleep_for(1ms);
        saw_stop = true;
    });
    require(eventually([&] { return running.load(); }), "task must start");
    active.cancel();
    require(ready(active.result, 1s) && active.result.get().status == Status::Cancelled, "running cancel");
    require(eventually([&] { return saw_stop.load() && pool.stats().running == 0; }), "job must see the stop");
    // Finished task: cancel is a no-op and the status stays.
    auto done = pool.submit({0, 0ms}, [](std::stop_token) {});
    require(ready(done.result), "task must finish");
    done.cancel();
    require(done.result.get().status == Status::Completed, "cancel after completion must not change status");
}

void capacity_freed_before_outcome_visible() {
    // One worker, and every task reserves the whole pool. The moment a Completed
    // or Failed outcome is observable, nothing may still be reserved or running.
    AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 2);
    for (int i = 0; i < 2000; ++i) {
        const bool fail = i % 2 == 1;
        auto ticket = pool.submit({1000, 0ms}, [fail](std::stop_token) {
            if (fail) throw std::runtime_error("expected");
        });
        // Spin instead of blocking, to observe the very first instant the outcome
        // is visible. A blocking wait wakes late and would hide an ordering bug.
        while (ticket.result.wait_for(0s) != std::future_status::ready) std::this_thread::yield();
        const auto outcome = ticket.result.get();
        require(outcome.status == (fail ? Status::Failed : Status::Completed), "unexpected status");
        const auto stats = pool.stats();
        require(stats.reserved_bytes == 0 && stats.running == 0,
                "capacity must be free by the time Completed or Failed is visible");
    }
}

void failures_release_capacity() {
    AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 4);
    auto thrown = pool.submit({500, 0ms}, [](std::stop_token) { throw std::runtime_error("boom"); });
    require(ready(thrown.result), "failed task must resolve");
    const auto failure = thrown.result.get();
    require(failure.status == Status::Failed && failure.message == "boom", "std::exception text must be kept");
    auto odd = pool.submit({500, 0ms}, [](std::stop_token) { throw 42; });
    require(ready(odd.result), "non-standard throw must resolve");
    const auto unknown = odd.result.get();
    require(unknown.status == Status::Failed && unknown.message == "unknown exception", "unknown exception");
    auto after = pool.submit({1000, 0ms}, [](std::stop_token) {});
    require(ready(after.result) && after.result.get().status == Status::Completed,
            "executor must keep working after failures");
    require(eventually([&] { return pool.stats().reserved_bytes == 0; }), "failures must release memory");
}

void shutdown_semantics() {
    // Default shutdown drains queued work.
    {
        AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 16);
        std::atomic<int> count{0};
        std::vector<Ticket> tickets;
        for (int i = 0; i < 10; ++i) tickets.push_back(pool.submit({0, 0ms}, [&](std::stop_token) { count++; }));
        pool.shutdown();
        pool.shutdown();  // idempotent
        require(count.load() == 10, "shutdown must drain every accepted job");
        for (auto& t : tickets) require(ready(t.result, 1s) && t.result.get().status == Status::Completed, "complete");
    }
    // shutdown(true) discards queued work but lets running jobs finish.
    {
        AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 8);
        Gate gate;
        std::atomic<bool> ran{false};
        auto running = pool.submit({0, 0ms}, gate.job());
        require(eventually([&] { return gate.started.load() == 1; }), "running task must start");
        std::vector<Ticket> queued;
        for (int i = 0; i < 3; ++i) queued.push_back(pool.submit({0, 0ms}, [&](std::stop_token) { ran = true; }));
        auto stopper = std::async(std::launch::async, [&] { pool.shutdown(true); });
        for (auto& t : queued) {
            require(ready(t.result, 5s) && t.result.get().status == Status::Cancelled, "queued must be Cancelled");
        }
        require(stopper.wait_for(50ms) == std::future_status::timeout, "shutdown must wait for the running job");
        gate.release.set_value();
        stopper.get();
        require(ready(running.result) && running.result.get().status == Status::Completed,
                "a running job must be allowed to finish");
        require(!ran.load(), "discarded jobs must never run");
    }
    // A job may not submit to or shut down its own executor.
    {
        AdmissionExecutor pool(budget(1, 1, 1000, 0, 0, 100), 2);
        std::atomic<bool> submit_threw{false}, shutdown_threw{false};
        auto ticket = pool.submit({0, 0ms}, [&](std::stop_token) {
            try { (void) pool.submit({0, 0ms}, [](std::stop_token) {}); } catch (const std::logic_error&) { submit_threw = true; }
            try { pool.shutdown(); } catch (const std::logic_error&) { shutdown_threw = true; }
        });
        require(ready(ticket.result) && ticket.result.get().status == Status::Completed, "job must finish");
        require(submit_threw.load() && shutdown_threw.load(), "recursive submit and shutdown must throw");
    }
}

void concurrent_stress() {
    constexpr std::uint64_t pool_bytes = 100000;
    constexpr int producers = 6, per_producer = 400;
    AdmissionExecutor pool(budget(8, 8, pool_bytes, 0, 0, 100), 32);
    std::atomic<std::uint64_t> in_use{0};
    std::atomic<bool> over_budget{false};
    std::atomic<int> executed{0};
    std::vector<std::thread> threads;
    std::vector<std::vector<Ticket>> all(producers);
    for (int p = 0; p < producers; ++p) {
        threads.emplace_back([&, p] {
            for (int i = 0; i < per_producer; ++i) {
                const std::uint64_t reserve = 100 + static_cast<std::uint64_t>((p * 7919 + i * 104729) % 40000);
                all[static_cast<std::size_t>(p)].push_back(pool.submit({reserve, 0ms}, [&, reserve](std::stop_token) {
                    if (in_use.fetch_add(reserve) + reserve > pool_bytes) over_budget = true;
                    executed.fetch_add(1);
                    if (reserve % 3 == 0) std::this_thread::yield();
                    in_use.fetch_sub(reserve);
                }));
            }
        });
    }
    for (auto& t : threads) t.join();
    int completed = 0;
    for (auto& group : all) {
        for (auto& t : group) {
            require(ready(t.result), "stress task must resolve");
            if (t.result.get().status == Status::Completed) ++completed;
        }
    }
    require(completed == producers * per_producer && executed.load() == completed, "every task must run once");
    require(!over_budget.load(), "running reservations must never exceed the pool");
    require(eventually([&] { return pool.stats().reserved_bytes == 0 && pool.stats().running == 0; }), "drained");
    const auto stats = pool.stats();
    require(stats.peak_reserved_bytes <= pool_bytes && stats.peak_running <= 8, "peaks must respect the limits");
}
} // namespace

int main() {
    // Backstop: any deadlock still ends the run, with a message, well before CI's timeout.
    std::thread([] {
        std::this_thread::sleep_for(120s);
        fail("timed out after 120 s (deadlock?)");
    }).detach();
    try {
        worker_limit_formula();
        memory_admission_limits_concurrency();
        reservation_addition_must_not_wrap();
        strict_fifo_admission();
        rejection();
        bounded_backpressure();
        timeouts();
        stop_callbacks_run_without_executor_locks();
        delayed_watchdog_does_not_hide_expired_completion();
        cancellation();
        capacity_freed_before_outcome_visible();
        failures_release_capacity();
        shutdown_semantics();
        concurrent_stress();
        std::cout << "admission tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "admission test failed: " << error.what() << '\n';
        return 1;
    }
}
