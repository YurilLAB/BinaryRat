// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <chrono>

namespace binaryrat::detail {

inline std::chrono::steady_clock::time_point deadline_after(std::chrono::milliseconds timeout) {
    using Clock = std::chrono::steady_clock;
    const auto now = Clock::now();
    // Both supported platforms use steady-clock ticks finer than milliseconds.
    // Check before converting: a positive millisecond count can otherwise
    // overflow the clock's duration representation during duration_cast.
    if (timeout > std::chrono::duration_cast<std::chrono::milliseconds>(Clock::duration::max())) {
        return Clock::time_point::max();
    }
    const auto delay = std::chrono::duration_cast<Clock::duration>(timeout);
    // max - positive delay is safe even if this clock's epoch makes now negative.
    if (now.time_since_epoch() > Clock::duration::max() - delay) {
        return Clock::time_point::max();
    }
    return now + delay;
}

} // namespace binaryrat::detail
