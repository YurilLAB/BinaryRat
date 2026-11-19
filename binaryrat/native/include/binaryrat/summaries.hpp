// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "binaryrat/types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binaryrat::types {

// One exact access through a function's pointer parameter. Offsets are relative
// to the parameter value and may be negative: a callee can receive an interior
// pointer that only the caller can place inside the object.
struct SummaryAccess {
    std::int64_t offset{0};
    std::uint64_t width{0};
    std::string evidence_id;
    std::optional<StorageView> storage_view{std::nullopt};
};

// Everything one function does directly with one pointer parameter.
struct ParameterSummary {
    std::string id;
    std::vector<SummaryAccess> accesses;
};

// A call passing the caller's parameter plus a constant byte offset as the
// callee's parameter: callee pointer == caller pointer + offset.
struct ForwardingEdge {
    std::size_t caller{0};
    std::size_t callee{0};
    std::int64_t offset{0};
    std::string evidence_id;
};

struct SolveRoot {
    std::size_t summary{0};
    // The analyst asserts that this parameter points at the object's start.
    std::string object_id;
};

struct SummarySolveOptions {
    std::uint64_t maximum_extent{std::uint64_t{1} << 32};
    // Per root. Exceeding either limit withholds that root's layout entirely.
    std::size_t maximum_states{4'096};
    std::size_t maximum_derived{16'384};
};

// A strongly connected set of summaries (or one summary that calls itself).
// It is consistent when every cycle in it adds up to offset zero; then every
// path between two members has the same offset. Otherwise the offsets along
// its cycles are unbounded, and its internal edges are withheld.
struct CallComponent {
    std::vector<std::size_t> summaries;
    bool consistent{true};
    std::vector<std::size_t> withheld_edges;
};

// One (summary, object offset) pair reached from a root. `edge` and `parent`
// name the first, shortest path found; follow `parent` back to the root.
struct ReachedState {
    std::size_t summary{0};
    std::int64_t offset{0};
    std::size_t hops{0};
    std::optional<std::size_t> edge;
    std::optional<std::size_t> parent;
};

struct DerivedAccess {
    std::size_t state{0};
    std::size_t access{0};
    std::int64_t offset{0};
};

enum class RootStatus {
    solved,
    state_limit,
    derived_limit,
};

[[nodiscard]] std::string_view to_string(RootStatus status) noexcept;

struct RootSolution {
    RootStatus status{RootStatus::solved};
    // Empty unless solved.
    std::vector<ReachedState> states;
    std::vector<DerivedAccess> derived;
    std::optional<RecoveredLayout> layout;
    // observation_index refers to `derived`.
    std::vector<RejectedObservation> rejected;
    // Inconsistent components whose withheld edges this root could have taken.
    std::vector<std::size_t> withheld_components;
    // Paths dropped because an offset sum left the signed 64-bit range.
    std::size_t overflowed{0};

    [[nodiscard]] bool complete() const noexcept {
        return status == RootStatus::solved && withheld_components.empty() && overflowed == 0;
    }
};

struct SummarySolution {
    // Components with more than one member or a self-call, ordered by their
    // smallest member ID; members are ordered by ID.
    std::vector<CallComponent> components;
    std::vector<RootSolution> roots;
};

// Propagates parameter summaries along forwarding edges. Every derived access
// corresponds to at least one concrete call path with the exact summed offset.
// Paths that would require an unbounded offset are withheld, never guessed.
// Results do not depend on the order of summaries or edges. Throws
// std::invalid_argument for empty or duplicate summary IDs and out-of-range indices.
[[nodiscard]] SummarySolution solve_summaries(
    const std::vector<ParameterSummary>& summaries,
    const std::vector<ForwardingEdge>& edges,
    const std::vector<SolveRoot>& roots,
    SummarySolveOptions options = {});

}  // namespace binaryrat::types
