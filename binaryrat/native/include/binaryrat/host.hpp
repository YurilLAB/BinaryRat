// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

// Facts about this machine and about other processes, used to size and police
// decompiler jobs. Windows and Linux are implemented; elsewhere the process
// queries report "unsupported" and machine() reports only the CPU count.
namespace binaryrat::host {

struct Machine {
    // CPUs this process may run on (affinity and Linux cgroup quota applied), at least 1.
    std::size_t logical_cpus = 1;
    // Physical memory, lowered to a Linux cgroup memory limit when one is set.
    // Zero when unknown.
    std::uint64_t physical_memory_bytes = 0;
};

[[nodiscard]] Machine machine();

[[nodiscard]] bool process_queries_supported() noexcept;

// A process named by PID together with its start time, so that a PID reused by a
// later process is never mistaken for the one that was identified.
struct ProcessId {
    std::uint64_t pid = 0;
    std::uint64_t start_stamp = 0;
    friend bool operator==(const ProcessId&, const ProcessId&) = default;
};

// The live process with this PID, or nullopt when there is none or it cannot be read.
[[nodiscard]] std::optional<ProcessId> identify(std::uint64_t pid);

// Resident memory (Windows working set, Linux RSS) of the identified process, or
// nullopt once it has exited or its PID belongs to another process.
[[nodiscard]] std::optional<std::uint64_t> resident_bytes(const ProcessId& process);

// Kills the identified process. Returns false, killing nothing, when the PID no
// longer names that process or the host cannot pin it for safe termination.
bool terminate(const ProcessId& process);

} // namespace binaryrat::host
