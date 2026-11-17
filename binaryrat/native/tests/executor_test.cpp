// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/executor.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <latch>
#include <stdexcept>
#include <vector>

using binaryrat::ThreadPool;
using namespace std::chrono_literals;

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template <class Exception, class Action>
void requires_throw(Action action) {
    try { action(); }
    catch (const Exception&) { return; }
    throw std::runtime_error("expected exception was not thrown");
}

void parallelism_and_drain() {
    ThreadPool pool(4, 8);
    std::atomic<int> active{0}, maximum{0}, count{0};
    std::latch running(4), release(1);
    std::vector<std::future<void>> tasks;
    for (int i = 0; i < 4; ++i) {
        tasks.push_back(pool.submit([&] {
            const auto current = active.fetch_add(1) + 1;
            auto old = maximum.load();
            while (old < current && !maximum.compare_exchange_weak(old, current)) {}
            running.count_down();
            release.wait();
            active.fetch_sub(1);
            count.fetch_add(1);
        }));
    }
    running.wait();
    const auto observed_maximum = maximum.load();
    release.count_down();
    require(observed_maximum == 4, "four workers must execute concurrently");
    for (int i = 0; i < 100; ++i) {
        tasks.push_back(pool.submit([&] { count.fetch_add(1); }));
    }
    pool.shutdown();
    for (auto& task : tasks) task.get();
    require(count.load() == 104, "shutdown must drain every accepted job");
    pool.shutdown();
    requires_throw<std::runtime_error>([&] { (void) pool.submit([] {}); });
}

void bounded_backpressure() {
    ThreadPool pool(1, 1);
    std::promise<void> entered, release, submitting;
    auto release_signal = release.get_future().share();
    auto first = pool.submit([&] { entered.set_value(); release_signal.wait(); });
    entered.get_future().wait();
    auto second = pool.submit([] {});
    auto producer = std::async(std::launch::async, [&] {
        submitting.set_value();
        return pool.submit([] {});
    });
    submitting.get_future().wait();
    const auto blocked = producer.wait_for(50ms) == std::future_status::timeout;
    release.set_value();
    require(blocked, "submit must block while the bounded pending queue is full");
    auto third = producer.get();
    first.get(); second.get(); third.get();
}

void exceptions_and_reentrancy() {
    ThreadPool pool(1, 2);
    auto failure = pool.submit([] { throw std::runtime_error("job failure"); });
    requires_throw<std::runtime_error>([&] { failure.get(); });
    auto recursion = pool.submit([&] { (void) pool.submit([] {}); });
    requires_throw<std::logic_error>([&] { recursion.get(); });
    auto self_stop = pool.submit([&] { pool.shutdown(); });
    requires_throw<std::logic_error>([&] { self_stop.get(); });
    auto success = pool.submit([] {});
    success.get();
    requires_throw<std::invalid_argument>([&] { (void) pool.submit({}); });
    requires_throw<std::invalid_argument>([] { ThreadPool invalid(0, 1); });
    requires_throw<std::invalid_argument>([] { ThreadPool invalid(1, 0); });
}
} // namespace

int main() {
    try {
        parallelism_and_drain();
        bounded_backpressure();
        exceptions_and_reentrancy();
        std::cout << "executor tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "executor test failed: " << error.what() << '\n';
        return 1;
    }
}
