// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace binaryrat::host::detail {

struct CgroupLimits {
    std::optional<std::uint64_t> cpu_workers;
    std::optional<std::uint64_t> memory_bytes;
};

using ReadFile = std::function<std::optional<std::string>(const std::string&)>;

// Linux only. The reader exposes process metadata and visible controller files.
[[nodiscard]] CgroupLimits cgroup_limits(const ReadFile& read);

} // namespace binaryrat::host::detail
