// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/executor.hpp>

#include <stdexcept>
#include <utility>

namespace binaryrat {
namespace {
thread_local ThreadPool* current_pool = nullptr;
}

ThreadPool::ThreadPool(std::size_t workers, std::size_t max_pending)
    : max_pending_(max_pending) {
    if (workers == 0 || max_pending == 0) {
        throw std::invalid_argument("executor requires positive workers and queue capacity");
    }
    try {
        threads_.reserve(workers);
        for (std::size_t i = 0; i < workers; ++i) {
            threads_.emplace_back([this] { run(); });
        }
    } catch (...) {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        ready_.notify_all();
        for (auto& thread : threads_) {
            thread.join();
        }
        throw;
    }
}

ThreadPool::~ThreadPool() {
    shutdown();
}

std::future<void> ThreadPool::submit(std::function<void()> job) {
    if (current_pool == this) {
        throw std::logic_error("a worker cannot submit recursively to its bounded executor");
    }
    if (!job) {
        throw std::invalid_argument("executor job must be callable");
    }
    std::packaged_task<void()> task(std::move(job));
    auto result = task.get_future();
    {
        std::unique_lock lock(mutex_);
        available_.wait(lock, [this] { return stopping_ || pending_.size() < max_pending_; });
        if (stopping_) {
            throw std::runtime_error("executor is shut down");
        }
        pending_.push_back(std::move(task));
    }
    ready_.notify_one();
    return result;
}

void ThreadPool::run() {
    current_pool = this;
    for (;;) {
        std::packaged_task<void()> task;
        {
            std::unique_lock lock(mutex_);
            ready_.wait(lock, [this] { return stopping_ || !pending_.empty(); });
            if (pending_.empty()) {
                current_pool = nullptr;
                return;
            }
            task = std::move(pending_.front());
            pending_.pop_front();
        }
        available_.notify_one();
        task(); // packaged_task transfers job exceptions to the future.
    }
}

void ThreadPool::shutdown() {
    if (current_pool == this) {
        throw std::logic_error("a worker cannot shut down its own executor");
    }
    std::lock_guard shutdown_lock(shutdown_mutex_);
    {
        std::lock_guard lock(mutex_);
        stopping_ = true;
    }
    ready_.notify_all();
    available_.notify_all();
    for (auto& thread : threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

} // namespace binaryrat
