// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include "../src/host_cgroups.hpp"

#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>

using binaryrat::host::detail::CgroupLimits;
using binaryrat::host::detail::cgroup_limits;

namespace {

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

struct Fixture {
    std::map<std::string, std::string> files;
    std::set<std::string> reads;

    CgroupLimits limits() {
        reads.clear();
        return cgroup_limits([&](const std::string& path) -> std::optional<std::string> {
            reads.insert(path);
            const auto location = files.find(path);
            if (location == files.end()) return std::nullopt;
            return location->second;
        });
    }
};

void nested_unified() {
    Fixture fixture{{
        {"/proc/self/cgroup", "0::/org/team/job/leaf\n"},
        {"/proc/self/mountinfo", "62 55 0:24 / /cg rw,nosuid - cgroup2 cgroup2 rw,nsdelegate\n"},
        {"/cg/org/team/job/leaf/memory.max", "max\n"},
        {"/cg/org/team/job/leaf/cpu.max", "max 100000\n"},
        {"/cg/org/team/job/memory.max", "max\n"},
        {"/cg/org/team/job/cpu.max", "240000 200000\n"},
        {"/cg/org/team/memory.max", "536870912\n"},
        {"/cg/org/team/cpu.max", "60000 100000\n"},
        {"/cg/org/memory.max", "1073741824\n"},
        {"/cg/org/cpu.max", "bad 100000\n"},
        {"/cg/memory.max", "4294967296\n"},
        {"/cg/cpu.max", "400000 100000\n"},
    }};
    auto limits = fixture.limits();
    require(limits.cpu_workers == 1, "tightest finite ancestor quota wins, including fractional CPU");
    require(limits.memory_bytes == 536870912, "intermediate RAM cap applies to an unlimited leaf");

    fixture.files["/cg/org/team/job/leaf/memory.max"] = "268435456\n";
    fixture.files["/cg/org/team/cpu.max"] = "0 0\n";
    limits = fixture.limits();
    require(limits.cpu_workers == 2, "compare quotas using each period and skip invalid limits");
    require(limits.memory_bytes == 268435456, "a tighter leaf limit still applies");
}

void bound_mounts_and_escaping() {
    Fixture fixture{{
        {"/proc/self/cgroup", "0::/tenant root/job:one/worker\n"},
        {"/proc/self/mountinfo",
            "62 55 0:24 /tenant /wrong rw - cgroup2 cgroup2 rw\n"
            "64 55 0:24 / /invalid/ rw - cgroup2 cgroup2 rw\n"
            "63 55 0:24 /tenant\\040root /mount\\040dir/cg\\134visible\\011tab\\012line rw shared:2 - cgroup2 cgroup2 rw\n"},
        {"/wrong/memory.max", "1\n"},
        {"/invalid/memory.max", "1\n"},
        {"/mount dir/memory.max", "2\n"},
        {"/sys/fs/cgroup/memory.max", "3\n"},
        {"/mount dir/cg\\visible\ttab\nline/job:one/memory.max", "65536\n"},
        {"/mount dir/cg\\visible\ttab\nline/cpu.max", "120000 100000\n"},
    }};
    const auto limits = fixture.limits();
    require(limits.cpu_workers == 2 && limits.memory_bytes == 65536,
            "resolve the mount-relative suffix and decode mountinfo escapes");
    require(!fixture.reads.contains("/wrong/memory.max") &&
            !fixture.reads.contains("/invalid/memory.max") &&
            !fixture.reads.contains("/mount dir/memory.max") &&
            !fixture.reads.contains("/sys/fs/cgroup/memory.max"),
            "do not read other binds or climb past the applicable mount boundary");
}

void split_v1_and_hybrid() {
    Fixture fixture{{
        {"/proc/self/cgroup", "0::/mem/jobs/worker\n5:cpu,cpuacct:/service/jobs/worker\n"},
        {"/proc/self/mountinfo",
            "61 55 0:21 / /unified rw - cgroup2 cgroup rw\n"
            "62 55 0:22 /service /legacy/cfs rw - cgroup cgroup rw,cpu,cpuacct\n"
            "63 55 0:23 / /fake rw - cgroup cgroup rw,cpuset\n"},
        {"/unified/mem/jobs/memory.max", "1073741824\n"},
        {"/unified/cpu.max", "max 100000\n"},
        {"/legacy/cfs/jobs/worker/cpu.cfs_quota_us", "-1\n"},
        {"/legacy/cfs/jobs/cpu.cfs_quota_us", "140000\n"},
        {"/legacy/cfs/jobs/cpu.cfs_period_us", "100000\n"},
        {"/fake/service/jobs/worker/cpu.cfs_quota_us", "10\n"},
        {"/fake/service/jobs/worker/cpu.cfs_period_us", "100000\n"},
    }};
    const auto limits = fixture.limits();
    require(limits.cpu_workers == 2 && limits.memory_bytes == 1073741824,
            "resolve applicable split hierarchies in a hybrid mount namespace");
    require(!fixture.reads.contains("/fake/service/jobs/worker/cpu.cfs_quota_us"),
            "select mount controllers by exact name");
}

void inherited_namespace_mount() {
    Fixture fixture{{
        {"/proc/self/cgroup", "0::/\n"},
        {"/proc/self/mountinfo",
            "62 55 0:24 /.. /inherited rw - cgroup2 cgroup2 rw\n"
            "63 55 0:24 /../sibling /sibling rw - cgroup2 cgroup2 rw\n"
            "64 55 0:23 /.. /legacy rw - cgroup cgroup rw,memory\n"},
        {"/inherited/cpu.max", "200000 100000\n"},
        {"/inherited/memory.max", "1073741824\n"},
        {"/sibling/memory.max", "1\n"},
        {"/legacy/memory.limit_in_bytes", "536870912\n"},
        {"/legacy/memory.use_hierarchy", "0\n"},
    }};
    const auto limits = fixture.limits();
    require(limits.cpu_workers == 2 && limits.memory_bytes == 1073741824,
            "limits at the inherited mount root apply when namespace components are hidden");
    require(!fixture.reads.contains("/sibling/memory.max"), "skip a sibling of the namespace root");

    fixture.files["/proc/self/cgroup"] = "0::/\n4:memory:/\n";
    fixture.files.erase("/inherited/memory.max");
    require(!fixture.limits().memory_bytes && !fixture.reads.contains("/legacy/memory.limit_in_bytes"),
            "skip legacy memory ancestors without hierarchical accounting");
    fixture.files["/legacy/memory.use_hierarchy"] = "1\n";
    require(fixture.limits().memory_bytes == 536870912,
            "v1 memory limits at an inherited root apply when hierarchical accounting is enabled");

    fixture.files["/proc/self/cgroup"] = "0::/../../other\n";
    const auto outside = fixture.limits();
    require(!outside.cpu_workers && !outside.memory_bytes && fixture.reads.size() == 2,
            "an inherited mount cannot constrain a process outside its subtree");
}

void v1_memory_hierarchy() {
    Fixture fixture{{
        {"/proc/self/cgroup", "4:memory:/tenant/job/worker\n"},
        {"/proc/self/mountinfo", "62 55 0:24 /tenant /memory rw - cgroup cgroup rw,memory\n"},
        {"/memory/job/worker/memory.limit_in_bytes", "9223372036854771712\n"},
        {"/memory/job/memory.limit_in_bytes", "1073741824\n"},
        {"/memory/memory.limit_in_bytes", "2147483648\n"},
    }};
    require(fixture.limits().memory_bytes == 1073741824, "walk v1 memory parents when stat is absent");
    fixture.files["/memory/job/worker/memory.stat"] =
        "cache 106496\nrss 311296\nhierarchical_memory_limit 536870912\n";
    require(fixture.limits().memory_bytes == 536870912,
            "use the v1 effective limit, including ancestors outside the visible mount");
    fixture.files["/memory/job/worker/memory.stat"] = "rss 311296\n";
    fixture.files["/memory/job/memory.use_hierarchy"] = "0\n";
    require(fixture.limits().memory_bytes == 9223372036854771712ULL,
            "skip v1 ancestors where disabled hierarchical accounting makes them inapplicable");
    require(!fixture.reads.contains("/memory/memory.limit_in_bytes"),
            "a disabled v1 parent ends its ancestry walk");
}

void fallback_and_invalid_input() {
    Fixture fixture{{
        {"/proc/self/cgroup", "0::/slice/leaf\n"},
        {"/sys/fs/cgroup/slice/leaf/memory.max", "0\n"},
        {"/sys/fs/cgroup/slice/leaf/cpu.max", "18446744073709551615 9223372036854775808\n"},
        {"/sys/fs/cgroup/slice/cpu.max", "18446744073709551616 100000\n"},
    }};
    auto limits = fixture.limits();
    require(limits.cpu_workers == 2 && limits.memory_bytes == 0,
            "fallback supports zero RAM and avoids CPU rounding overflow");

    fixture.files["/proc/self/cgroup"] = "0::/../escape/leaf\n";
    fixture.files["/sys/fs/cgroup/../escape/leaf/memory.max"] = "1\n";
    limits = fixture.limits();
    require(!limits.cpu_workers && !limits.memory_bytes && fixture.reads.size() == 2,
            "membership that escapes a mount cannot force reads outside it");

    fixture.files["/proc/self/cgroup"] = "4:cpu,cpuacct:/team/leaf\n";
    fixture.files["/sys/fs/cgroup/cpu,cpuacct/team/cpu.cfs_quota_us"] = "200000\n";
    fixture.files["/sys/fs/cgroup/cpu,cpuacct/team/cpu.cfs_period_us"] = "100000\n";
    require(fixture.limits().cpu_workers == 2, "legacy combined mount fallback includes ancestors");
}

} // namespace

int main() {
    try {
        nested_unified();
        bound_mounts_and_escaping();
        split_v1_and_hybrid();
        inherited_namespace_mount();
        v1_memory_hierarchy();
        fallback_and_invalid_input();
    }
    catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
