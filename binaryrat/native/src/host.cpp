// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/host.hpp>

#include <algorithm>
#include <bit>
#include <limits>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#elif defined(__linux__)
#include <cerrno>
#include <charconv>
#include <csignal>
#include <fstream>
#include <sched.h>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace binaryrat::host {
namespace {

std::size_t standard_cpus() {
    return std::max<std::size_t>(1, std::thread::hardware_concurrency());
}

#ifdef _WIN32

class Handle {
public:
    explicit Handle(HANDLE handle) : handle_(handle) {}
    ~Handle() {
        if (handle_) CloseHandle(handle_);
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    [[nodiscard]] HANDLE get() const { return handle_; }
    explicit operator bool() const { return handle_ != nullptr; }

private:
    HANDLE handle_;
};

Handle open(std::uint64_t pid, DWORD access) {
    if (pid == 0 || pid > std::numeric_limits<DWORD>::max()) return Handle(nullptr);
    return Handle(OpenProcess(access | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                              static_cast<DWORD>(pid)));
}

// Creation time of a process that is still running; nullopt after it exits.
std::optional<std::uint64_t> running_since(HANDLE process) {
    if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT) return std::nullopt;
    FILETIME created, exited, kernel, user;
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return std::nullopt;
    return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

bool same_process(HANDLE process, const ProcessId& expected) {
    const auto since = running_since(process);
    return since && *since == expected.start_stamp;
}

#elif defined(__linux__)

std::optional<std::string> read_text(const std::string& path) {
    std::ifstream input(path);
    if (!input) return std::nullopt;
    std::ostringstream text;
    text << input.rdbuf();
    if (input.bad()) return std::nullopt;
    return text.str();
}

std::optional<std::uint64_t> parse_unsigned(std::string_view text) {
    while (!text.empty() && (text.back() == '\n' || text.back() == ' ')) text.remove_suffix(1);
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()) return std::nullopt;
    return value;
}

// Start time (clock ticks since boot, field 22 of /proc/PID/stat) of a process that
// is still running; zombies count as exited.
std::optional<std::uint64_t> running_since(std::uint64_t pid) {
    const auto stat = read_text("/proc/" + std::to_string(pid) + "/stat");
    if (!stat) return std::nullopt;
    // The command name (field 2) may hold spaces and parentheses; fields resume
    // after the last ')'.
    const auto close = stat->rfind(')');
    if (close == std::string::npos) return std::nullopt;
    std::istringstream fields(stat->substr(close + 1));
    std::string field;
    for (int index = 3; index <= 22; ++index) {
        if (!(fields >> field)) return std::nullopt;
        if (index == 3 && (field == "Z" || field == "X" || field == "x")) return std::nullopt;
    }
    return parse_unsigned(field);
}

std::string own_cgroup() {
    const auto groups = read_text("/proc/self/cgroup");
    if (!groups) return {};
    std::istringstream lines(*groups);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.rfind("0::", 0) == 0) return line.substr(3);
    }
    return {};
}

std::optional<std::uint64_t> cgroup_memory_limit() {
    const auto group = own_cgroup();
    for (const auto& path : {"/sys/fs/cgroup" + group + "/memory.max",
                             std::string("/sys/fs/cgroup/memory.max"),
                             std::string("/sys/fs/cgroup/memory/memory.limit_in_bytes")}) {
        if (const auto text = read_text(path)) {
            if (const auto value = parse_unsigned(*text)) return value;
        }
    }
    return std::nullopt;
}

std::optional<std::size_t> cgroup_cpu_limit() {
    const auto text = read_text("/sys/fs/cgroup" + own_cgroup() + "/cpu.max");
    if (!text) return std::nullopt;
    std::istringstream fields(*text);
    std::string quota, period;
    if (!(fields >> quota >> period) || quota == "max") return std::nullopt;
    const auto q = parse_unsigned(quota), p = parse_unsigned(period);
    if (!q || !p || *p == 0) return std::nullopt;
    return static_cast<std::size_t>(std::max<std::uint64_t>(1, (*q + *p - 1) / *p));
}

#endif

} // namespace

Machine machine() {
    Machine result;
    result.logical_cpus = standard_cpus();
#ifdef _WIN32
    DWORD_PTR process_mask = 0, system_mask = 0;
    if (GetProcessAffinityMask(GetCurrentProcess(), &process_mask, &system_mask) && process_mask)
        result.logical_cpus = std::min<std::size_t>(
            result.logical_cpus, static_cast<std::size_t>(std::popcount(process_mask)));
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) result.physical_memory_bytes = status.ullTotalPhys;
#elif defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof(set), &set) == 0 && CPU_COUNT(&set) > 0)
        result.logical_cpus = static_cast<std::size_t>(CPU_COUNT(&set));
    if (const auto quota = cgroup_cpu_limit())
        result.logical_cpus = std::min(result.logical_cpus, *quota);
    const long pages = sysconf(_SC_PHYS_PAGES);
    const long page_size = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && page_size > 0)
        result.physical_memory_bytes =
            static_cast<std::uint64_t>(pages) * static_cast<std::uint64_t>(page_size);
    if (const auto limit = cgroup_memory_limit(); limit && *limit > 0 &&
        (result.physical_memory_bytes == 0 || *limit < result.physical_memory_bytes))
        result.physical_memory_bytes = *limit;
#endif
    return result;
}

bool process_queries_supported() noexcept {
#if defined(_WIN32) || defined(__linux__)
    return true;
#else
    return false;
#endif
}

std::optional<ProcessId> identify(std::uint64_t pid) {
#ifdef _WIN32
    const auto process = open(pid, 0);
    if (!process) return std::nullopt;
    const auto since = running_since(process.get());
    if (!since) return std::nullopt;
    return ProcessId{pid, *since};
#elif defined(__linux__)
    if (pid == 0 || pid > static_cast<std::uint64_t>(std::numeric_limits<pid_t>::max()))
        return std::nullopt;
    const auto since = running_since(pid);
    if (!since) return std::nullopt;
    return ProcessId{pid, *since};
#else
    (void)pid;
    return std::nullopt;
#endif
}

std::optional<std::uint64_t> resident_bytes(const ProcessId& process) {
#ifdef _WIN32
    const auto handle = open(process.pid, 0);
    if (!handle || !same_process(handle.get(), process)) return std::nullopt;
    PROCESS_MEMORY_COUNTERS counters{};
    if (!GetProcessMemoryInfo(handle.get(), &counters, sizeof(counters))) return std::nullopt;
    return static_cast<std::uint64_t>(counters.WorkingSetSize);
#elif defined(__linux__)
    if (running_since(process.pid) != process.start_stamp) return std::nullopt;
    const auto statm = read_text("/proc/" + std::to_string(process.pid) + "/statm");
    if (!statm) return std::nullopt;
    std::istringstream fields(*statm);
    std::uint64_t size = 0, resident = 0;
    if (!(fields >> size >> resident)) return std::nullopt;
    // Re-check after reading so a PID recycled in between is not reported.
    if (running_since(process.pid) != process.start_stamp) return std::nullopt;
    const long page_size = sysconf(_SC_PAGE_SIZE);
    return resident * static_cast<std::uint64_t>(page_size > 0 ? page_size : 4096);
#else
    (void)process;
    return std::nullopt;
#endif
}

bool terminate(const ProcessId& process) {
#ifdef _WIN32
    const auto handle = open(process.pid, PROCESS_TERMINATE);
    // The open handle pins the process object, so the identity check and the
    // termination below refer to the same process.
    if (!handle || !same_process(handle.get(), process)) return false;
    return TerminateProcess(handle.get(), 1) != 0;
#elif defined(__linux__)
    if (running_since(process.pid) != process.start_stamp) return false;
    return kill(static_cast<pid_t>(process.pid), SIGKILL) == 0;
#else
    (void)process;
    return false;
#endif
}

} // namespace binaryrat::host
