// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include "host_cgroups.hpp"

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <sstream>
#include <string_view>

namespace binaryrat::host::detail {
namespace {

using Path = std::filesystem::path;

struct Memberships {
    Path unified;
    Path cpu;
    Path memory;
};

bool has_controller(std::string_view options, std::string_view controller) {
    while (!options.empty()) {
        const auto separator = options.find(',');
        if (options.substr(0, separator) == controller) return true;
        if (separator == std::string_view::npos) break;
        options.remove_prefix(separator + 1);
    }
    return false;
}

Memberships parse_memberships(const std::string& text) {
    Memberships result;
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        const auto id_end = line.find(':');
        if (id_end == std::string::npos) continue;
        const auto options_end = line.find(':', id_end + 1);
        if (options_end == std::string::npos) continue;
        const std::string_view options(line.data() + id_end + 1, options_end - id_end - 1);
        const Path path(line.substr(options_end + 1));
        if (!path.is_absolute()) continue;
        if (id_end == 1 && line.front() == '0' && options.empty()) result.unified = path;
        if (has_controller(options, "cpu")) result.cpu = path;
        if (has_controller(options, "memory")) result.memory = path;
    }
    return result;
}

Path decode_mount_path(std::string_view text) {
    std::string result;
    for (std::size_t index = 0; index < text.size(); ++index) {
        if (text[index] == '\\' && text.size() - index >= 4) {
            const auto escaped = text.substr(index + 1, 3);
            char character = '\0';
            if (escaped == "040") character = ' ';
            if (escaped == "011") character = '\t';
            if (escaped == "012") character = '\n';
            if (escaped == "134") character = '\\';
            if (character) {
                result += character;
                index += 3;
                continue;
            }
        }
        result += text[index];
    }
    return Path(result);
}

std::optional<Path> mounted_group(const Path& membership, const Path& root, const Path& mount) {
    if (!membership.is_absolute() || !root.is_absolute()) return std::nullopt;

    // Match whole components. A bind mount of /team cannot expose /team2,
    // and cgroup namespace-relative paths must never escape the mount point.
    auto part = membership.begin();
    for (const auto& component : root) {
        if (part == membership.end() || *part != component) return std::nullopt;
        ++part;
    }
    auto leaf = mount;
    for (; part != membership.end(); ++part) {
        if (*part == ".." || *part == "." || part->empty()) return std::nullopt;
        leaf /= *part;
    }
    return leaf;
}

bool mount_above_namespace(const Path& root, const Path& membership) {
    if (!root.is_absolute() || !membership.is_absolute()) return false;
    // An inherited mount can show /.. or /../.. when it starts above the
    // namespace root. Such a mount is an ancestor even when the namespace
    // hides the intervening cgroup names needed to find our exact directory.
    std::size_t levels = 0;
    for (const auto& part : root.relative_path()) {
        if (part != "..") return false;
        ++levels;
    }
    for (const auto& part : membership.relative_path()) {
        if (part != ".." || levels == 0) break;
        --levels;
    }
    return levels > 0;
}

std::optional<std::uint64_t> number(std::string_view token) {
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(token.data(), token.data() + token.size(), value);
    if (error != std::errc{} || end != token.data() + token.size()) return std::nullopt;
    return value;
}

std::optional<std::uint64_t> read_number(const ReadFile& read, const Path& path) {
    const auto text = read(path.string());
    if (!text) return std::nullopt;
    std::istringstream fields(*text);
    std::string token, extra;
    if (!(fields >> token) || (fields >> extra)) return std::nullopt;
    return number(token);
}

void apply_limit(std::optional<std::uint64_t>& limit, std::optional<std::uint64_t> value) {
    if (value && (!limit || *value < *limit)) limit = value;
}

void scan_cpu(const ReadFile& read, const Path& leaf, const Path& mount, bool unified,
              CgroupLimits& limits) {
    for (auto directory = leaf;; directory = directory.parent_path()) {
        std::optional<std::uint64_t> quota, period;
        if (unified) {
            if (const auto value = read((directory / "cpu.max").string())) {
                std::istringstream fields(*value);
                std::string q, p, extra;
                if ((fields >> q >> p) && !(fields >> extra)) {
                    quota = number(q);
                    period = number(p);
                }
            }
        }
        else {
            quota = read_number(read, directory / "cpu.cfs_quota_us");
            if (quota) period = read_number(read, directory / "cpu.cfs_period_us");
        }
        if (quota && period && *period > 0) {
            // Preserve fractional-quota rounding without adding to the quota.
            const auto workers = *quota / *period + (*quota % *period != 0);
            apply_limit(limits.cpu_workers, std::max<std::uint64_t>(1, workers));
        }
        if (directory == mount) break;
    }
}

std::optional<std::uint64_t> hierarchical_memory_limit(const ReadFile& read, const Path& leaf) {
    const auto stat = read((leaf / "memory.stat").string());
    if (!stat) return std::nullopt;
    std::istringstream fields(*stat);
    std::string name, value;
    while (fields >> name >> value) {
        if (name == "hierarchical_memory_limit") return number(value);
    }
    return std::nullopt;
}

void scan_memory(const ReadFile& read, const Path& leaf, const Path& mount, bool unified,
                 CgroupLimits& limits) {
    if (!unified) {
        // v1 exposes the effective limit even when an ancestor is outside the mount.
        if (const auto hierarchical = hierarchical_memory_limit(read, leaf)) {
            apply_limit(limits.memory_bytes, hierarchical);
            return;
        }
    }
    const auto file = unified ? "memory.max" : "memory.limit_in_bytes";
    for (auto directory = leaf;; directory = directory.parent_path()) {
        // Older v1 kernels could disable hierarchical accounting at an ancestor.
        if (!unified && directory != leaf &&
            read_number(read, directory / "memory.use_hierarchy") == 0) break;
        apply_limit(limits.memory_bytes, read_number(read, directory / file));
        if (directory == mount) break;
    }
}

void scan(const ReadFile& read, const Path& root, const Path& mount, const Path& cpu,
          const Path& memory, bool unified, CgroupLimits& limits) {
    if (!mount.is_absolute() || (mount.has_relative_path() && !mount.has_filename())) return;
    if (const auto leaf = mounted_group(cpu, root, mount))
        scan_cpu(read, *leaf, mount, unified, limits);
    else if (mount_above_namespace(root, cpu))
        scan_cpu(read, mount, mount, unified, limits);
    if (const auto leaf = mounted_group(memory, root, mount))
        scan_memory(read, *leaf, mount, unified, limits);
    else if (mount_above_namespace(root, memory) &&
             (unified || read_number(read, mount / "memory.use_hierarchy") == 1))
        scan_memory(read, mount, mount, unified, limits);
}

} // namespace

CgroupLimits cgroup_limits(const ReadFile& read) {
    CgroupLimits result;
    const auto membership = read("/proc/self/cgroup");
    const auto groups = membership ? parse_memberships(*membership) : Memberships{};
    if (const auto metadata = read("/proc/self/mountinfo")) {
        std::istringstream lines(*metadata);
        std::string line;
        while (std::getline(lines, line)) {
            const auto separator = line.find(" - ");
            if (separator == std::string::npos) continue;
            std::istringstream fields(line.substr(separator + 3));
            std::string filesystem, source, options;
            if (!(fields >> filesystem >> source >> options) ||
                (filesystem != "cgroup" && filesystem != "cgroup2")) continue;
            std::istringstream prefix(line.substr(0, separator));
            std::string id, parent, device, root, mount;
            if (!(prefix >> id >> parent >> device >> root >> mount)) continue;

            const auto root_path = decode_mount_path(root);
            const auto mount_path = decode_mount_path(mount);
            if (filesystem == "cgroup2") {
                scan(read, root_path, mount_path, groups.unified, groups.unified, true, result);
            }
            else {
                const auto cpu = has_controller(options, "cpu") ? groups.cpu : Path{};
                const auto memory = has_controller(options, "memory") ? groups.memory : Path{};
                scan(read, root_path, mount_path, cpu, memory, false, result);
            }
        }
    }
    else {
        // Keep the conventional mount points as a fallback if mount metadata
        // cannot be read. Without membership only their roots are visible here.
        const Path root("/");
        const Path unified = membership ? groups.unified : root;
        const Path cpu = membership ? groups.cpu : root;
        const Path memory = membership ? groups.memory : root;
        scan(read, root, "/sys/fs/cgroup", unified, unified, true, result);
        scan(read, root, "/sys/fs/cgroup/memory", {}, memory, false, result);
        for (const auto* mount : {"/sys/fs/cgroup/cpu", "/sys/fs/cgroup/cpu,cpuacct",
                                  "/sys/fs/cgroup/cpuacct,cpu"})
            scan(read, root, mount, cpu, {}, false, result);
    }
    return result;
}

} // namespace binaryrat::host::detail
