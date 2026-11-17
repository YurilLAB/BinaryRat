// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <thread>
#include <vector>

namespace binaryrat {

// At most workers jobs execute and max_pending additional jobs queue. submit()
// applies backpressure. shutdown() drains accepted jobs and rejects new work.
// Jobs must not submit to or shut down their own pool: blocking recursive use
// could deadlock a bounded executor, so these calls throw std::logic_error.
class ThreadPool {
public:
    ThreadPool(std::size_t workers, std::size_t max_pending);
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    [[nodiscard]] std::future<void> submit(std::function<void()> job);
    void shutdown();

private:
    void run();

    const std::size_t max_pending_;
    std::mutex mutex_;
    std::mutex shutdown_mutex_;
    std::condition_variable ready_;
    std::condition_variable available_;
    std::deque<std::packaged_task<void()>> pending_;
    std::vector<std::thread> threads_;
    bool stopping_ = false;
};

} // namespace binaryrat
