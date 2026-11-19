// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

#include "binaryrat/summaries.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace {

using namespace binaryrat::types;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

SummaryAccess access(std::int64_t offset, std::uint64_t width, std::string evidence,
                     std::optional<StorageView> view = std::nullopt) {
    return {offset, width, std::move(evidence), view};
}

// Builds summaries by ID so tests read as call graphs.
struct Builder {
    std::vector<ParameterSummary> summaries;
    std::vector<ForwardingEdge> edges;
    std::map<std::string, std::size_t> index;

    std::size_t node(const std::string& id, std::vector<SummaryAccess> accesses = {}) {
        index[id] = summaries.size();
        summaries.push_back({id, std::move(accesses)});
        return summaries.size() - 1;
    }
    void call(const std::string& caller, const std::string& callee, std::int64_t offset,
              std::string evidence = {}) {
        if (evidence.empty()) {
            evidence = caller + "->" + callee + "@" + std::to_string(offset);
        }
        edges.push_back({index.at(caller), index.at(callee), offset, std::move(evidence)});
    }
    SummarySolution solve(const std::string& root, SummarySolveOptions options = {}) const {
        return solve_summaries(summaries, edges, {{index.at(root), "object"}}, options);
    }
};

std::vector<std::int64_t> derived_offsets(const RootSolution& root) {
    std::vector<std::int64_t> offsets;
    for (const auto& derived : root.derived) {
        offsets.push_back(derived.offset);
    }
    std::sort(offsets.begin(), offsets.end());
    return offsets;
}

void chain_shift_and_interior_pointer() {
    Builder graph;
    graph.node("root", {access(0, 8, "root-load")});
    graph.node("a", {access(0, 4, "a-load")});
    // The callee gets an interior pointer and steps back to the object start.
    graph.node("b", {access(-8, 4, "b-container")});
    graph.call("root", "a", 16);
    graph.call("a", "b", 8);
    const auto solution = graph.solve("root");
    const auto& root = solution.roots.at(0);
    require(root.complete(), "acyclic chain marked incomplete");
    require(root.states.size() == 3, "chain states missing");
    require(root.states[1].offset == 16 && root.states[2].offset == 24,
            "argument offsets not summed along the path");
    require(root.states[2].hops == 2 && root.states[2].parent == 1 &&
                root.states[2].edge == 1,
            "shortest path provenance lost");
    require(derived_offsets(root) == std::vector<std::int64_t>({0, 16, 16}),
            "derived offsets wrong");
    require(root.layout && root.layout->fields.size() == 2, "layout fields wrong");
    const auto& field = root.layout->fields[1];
    require(field.offset == 16 && field.width == 4 && field.evidence_count() == 2,
            "interior-pointer access did not join the caller's field");
    require(solution.components.empty(), "acyclic graph reported a component");
}

void diamonds() {
    Builder same;
    same.node("root");
    same.node("a");
    same.node("b");
    same.node("c", {access(0, 4, "c-load")});
    same.call("root", "a", 8);
    same.call("root", "b", 0);
    same.call("a", "c", 0);
    same.call("b", "c", 8);
    const auto joined = same.solve("root").roots.at(0);
    require(joined.states.size() == 4, "equal-offset diamond duplicated a state");
    require(derived_offsets(joined) == std::vector<std::int64_t>({8}),
            "equal-offset diamond duplicated evidence");
    require(joined.states.back().parent == 1, "first path is not canonical (a before b)");

    Builder split;
    split.node("root");
    split.node("a");
    split.node("b");
    split.node("c", {access(4, 4, "c-load")});
    split.call("root", "a", 0);
    split.call("root", "b", 8);
    split.call("a", "c", 0);
    split.call("b", "c", 0);
    const auto both = split.solve("root").roots.at(0);
    require(derived_offsets(both) == std::vector<std::int64_t>({4, 12}),
            "different-offset paths must give separate facts");
    require(both.layout && both.layout->fields.size() == 2 &&
                both.layout->fields[0].evidence_ids == both.layout->fields[1].evidence_ids,
            "one instruction must support both reached offsets");
}

void consistent_cycles() {
    Builder mutual;
    mutual.node("a", {access(0, 8, "a-load")});
    mutual.node("b", {access(0, 4, "b-load")});
    mutual.call("a", "b", 8);
    mutual.call("b", "a", -8);
    const auto solution = mutual.solve("a");
    require(solution.components.size() == 1 && solution.components[0].consistent,
            "zero-sum cycle not consistent");
    require(solution.components[0].summaries == std::vector<std::size_t>({0, 1}),
            "component members not ordered by ID");
    const auto& root = solution.roots.at(0);
    require(root.complete() && root.states.size() == 2, "consistent cycle not solved");
    require(derived_offsets(root) == std::vector<std::int64_t>({0, 8}), "cycle offsets wrong");

    Builder self;
    self.node("walk", {access(0, 8, "load")});
    self.call("walk", "walk", 0);
    const auto recursion = self.solve("walk");
    require(recursion.components.size() == 1 && recursion.components[0].consistent,
            "zero-offset self call not reported as a consistent component");
    require(recursion.roots[0].states.size() == 1 && recursion.roots[0].complete(),
            "zero-offset recursion added states");

    Builder triangle;
    triangle.node("a");
    triangle.node("b");
    triangle.node("c", {access(0, 4, "c")});
    triangle.call("a", "b", 8);
    triangle.call("b", "c", 8);
    triangle.call("c", "a", -16);
    const auto three = triangle.solve("a");
    require(three.components.size() == 1 && three.components[0].consistent,
            "zero-sum three-cycle not consistent");
    require(derived_offsets(three.roots[0]) == std::vector<std::int64_t>({16}),
            "three-cycle offsets wrong");
}

void inconsistent_cycles_withhold() {
    Builder list;
    list.node("walk", {access(0, 8, "next"), access(8, 4, "value")});
    list.call("walk", "walk", 16);
    const auto walk = list.solve("walk");
    require(walk.components.size() == 1 && !walk.components[0].consistent,
            "nonzero self call reported consistent");
    require(walk.components[0].withheld_edges == std::vector<std::size_t>({0}),
            "self call not withheld");
    const auto& root = walk.roots.at(0);
    require(!root.complete() && root.withheld_components == std::vector<std::size_t>({0}),
            "root does not say what was withheld");
    require(derived_offsets(root) == std::vector<std::int64_t>({0, 8}),
            "direct accesses must remain exact");

    Builder entered;
    entered.node("root", {access(0, 4, "root")});
    entered.node("a", {access(0, 4, "a")});
    entered.node("b", {access(4, 4, "b-only-via-cycle")});
    entered.node("leaf", {access(0, 2, "leaf")});
    entered.call("root", "a", 0);
    entered.call("a", "b", 8);
    entered.call("b", "a", 0);
    entered.call("a", "leaf", 32);
    const auto reached = entered.solve("root").roots.at(0);
    require(!reached.complete(), "withheld component not reported");
    require(derived_offsets(reached) == std::vector<std::int64_t>({0, 0, 32}),
            "edges inside an unbounded component were followed");

    // Parallel edges make a cycle inconsistent although each simple cycle
    // through one of them alone is zero-sum.
    Builder parallel;
    parallel.node("a", {access(0, 4, "a")});
    parallel.node("b", {access(0, 4, "b")});
    parallel.call("a", "b", 0, "first");
    parallel.call("a", "b", 8, "second");
    parallel.call("b", "a", 0);
    const auto conflict = parallel.solve("a");
    require(!conflict.components.at(0).consistent, "parallel offsets missed");
    require(conflict.components[0].withheld_edges.size() == 3, "not all internal edges withheld");
}

void overflow_and_rejection() {
    const auto max = std::numeric_limits<std::int64_t>::max();
    Builder graph;
    graph.node("root");
    graph.node("far", {access(1, 1, "past-the-end"), access(-1, 1, "fits")});
    graph.node("farther", {access(0, 1, "never")});
    graph.call("root", "far", max);
    graph.call("far", "farther", 1);
    const auto root = graph.solve("root").roots.at(0);
    require(root.overflowed == 2 && !root.complete(), "overflow not counted");
    require(derived_offsets(root) == std::vector<std::int64_t>({max - 1}),
            "overflow dropped the wrong access");
    require(root.rejected.size() == 1 && root.rejected[0].reason == RejectionReason::extent_limit,
            "an out-of-extent derived access was not rejected");

    // Every cycle sums to zero, but member positions leave the signed range:
    // the component cannot be placed in one frame, so it is withheld.
    Builder far_ring;
    far_ring.node("a", {access(0, 1, "a")});
    far_ring.node("b", {access(0, 1, "b")});
    far_ring.node("c", {access(0, 1, "c")});
    far_ring.call("a", "b", max);
    far_ring.call("b", "c", 1);
    far_ring.call("c", "a", std::numeric_limits<std::int64_t>::min());
    const auto ring = far_ring.solve("a");
    require(ring.components.size() == 1 && !ring.components[0].consistent &&
                ring.components[0].withheld_edges.size() == 3,
            "positions outside the signed range were accepted");

    Builder negative;
    negative.node("root");
    negative.node("callee", {access(0, 4, "before-start")});
    negative.call("root", "callee", -8);
    const auto before = negative.solve("root").roots.at(0);
    require(before.rejected.size() == 1 && before.rejected[0].observation_index == 0 &&
                before.rejected[0].reason == RejectionReason::negative_offset,
            "a derived access before the object start was accepted");
    require(!before.layout, "a fully rejected root produced a layout");
}

void limits_fail_closed() {
    Builder chain;
    chain.node("a", {access(0, 1, "a")});
    chain.node("b", {access(0, 1, "b")});
    chain.node("c", {access(0, 1, "c")});
    chain.call("a", "b", 1);
    chain.call("b", "c", 1);
    SummarySolveOptions options;
    options.maximum_states = 2;
    const auto states = chain.solve("a", options).roots.at(0);
    require(states.status == RootStatus::state_limit && states.states.empty() &&
                states.derived.empty() && !states.layout && !states.complete(),
            "state limit must withhold the root");
    options.maximum_states = 3;
    require(chain.solve("a", options).roots[0].status == RootStatus::solved,
            "exact state limit refused");
    options.maximum_derived = 2;
    const auto derived = chain.solve("a", options).roots.at(0);
    require(derived.status == RootStatus::derived_limit && !derived.layout,
            "derived limit must withhold the root");
    options.maximum_derived = 3;
    require(chain.solve("a", options).roots[0].status == RootStatus::solved,
            "exact derived limit refused");
    options.maximum_states = 0;
    require(chain.solve("a", options).roots[0].status == RootStatus::state_limit,
            "zero state limit accepted a root");
}

void invalid_input() {
    const auto throws = [](auto&& action) {
        try {
            action();
        } catch (const std::invalid_argument&) {
            return true;
        }
        return false;
    };
    require(throws([] { (void)solve_summaries({{"", {}}}, {}, {}); }), "empty ID accepted");
    require(throws([] { (void)solve_summaries({{"a", {}}, {"a", {}}}, {}, {}); }),
            "duplicate ID accepted");
    require(throws([] { (void)solve_summaries({{"a", {}}}, {{0, 1, 0, "e"}}, {}); }),
            "unknown callee accepted");
    require(throws([] { (void)solve_summaries({{"a", {}}}, {}, {{1, "o"}}); }),
            "unknown root accepted");
    const auto empty = solve_summaries({}, {}, {});
    require(empty.roots.empty() && empty.components.empty(), "empty input invented output");
}

void typed_views_cross_calls() {
    Builder graph;
    graph.node("root", {access(8, 8, "float-here", StorageView::floating_point)});
    graph.node("callee", {access(0, 8, "integer-there", StorageView::integer)});
    graph.call("root", "callee", 8);
    const auto root = graph.solve("root").roots.at(0);
    require(root.layout && root.layout->union_candidates.size() == 1 &&
                root.layout->union_candidates[0].offset == 8,
            "typed views from a callee did not meet the caller's view");
}

void duplicates_and_roots() {
    Builder graph;
    graph.node("root", {access(0, 4, "r")});
    graph.node("other", {access(0, 4, "o")});
    graph.node("callee", {access(0, 4, "c")});
    graph.node("unreached", {access(0, 4, "u")});
    graph.call("root", "callee", 4, "site");
    graph.call("root", "callee", 4, "site");
    graph.call("other", "callee", 0);
    const auto solution = solve_summaries(graph.summaries, graph.edges,
                                          {{0, "first"}, {1, "second"}});
    const auto& first = solution.roots.at(0);
    require(first.states.size() == 2 && first.states[1].edge == 0,
            "duplicate edge not collapsed onto the lowest index");
    require(first.layout && first.layout->object_id == "first", "root object ID lost");
    require(derived_offsets(solution.roots.at(1)) == std::vector<std::int64_t>({0, 0}),
            "roots are not independent");
    for (const auto& root : solution.roots) {
        for (const auto& state : root.states) {
            require(state.summary != 3, "unreachable summary used");
        }
    }
}

// Maps a solution to IDs and values so differently ordered inputs compare equal.
using Fact = std::tuple<std::string, std::int64_t, std::size_t, std::string, std::int64_t>;
std::vector<Fact> facts(const std::vector<ParameterSummary>& summaries, const RootSolution& root) {
    std::vector<Fact> result;
    for (const auto& derived : root.derived) {
        const auto& state = root.states[derived.state];
        const auto& summary = summaries[state.summary];
        result.emplace_back(summary.id, state.offset, state.hops,
                            summary.accesses[derived.access].evidence_id, derived.offset);
    }
    std::sort(result.begin(), result.end());
    return result;
}

void permutation_stability() {
    std::mt19937_64 random(20261119);
    for (int round = 0; round < 200; ++round) {
        const int count = 2 + static_cast<int>(random() % 7);
        std::vector<ParameterSummary> summaries;
        for (int index = 0; index < count; ++index) {
            ParameterSummary summary{"s" + std::to_string(index), {}};
            const int accesses = static_cast<int>(random() % 3);
            for (int item = 0; item < accesses; ++item) {
                summary.accesses.push_back(access(static_cast<std::int64_t>(random() % 5) * 4 - 4, 4,
                    summary.id + "-" + std::to_string(item)));
            }
            summaries.push_back(std::move(summary));
        }
        std::vector<ForwardingEdge> edges;
        const int edge_count = static_cast<int>(random() % (2 * count));
        for (int index = 0; index < edge_count; ++index) {
            edges.push_back({random() % count, random() % count,
                static_cast<std::int64_t>(random() % 3) * 8 - 8, "e" + std::to_string(index % 3)});
        }
        const auto base = solve_summaries(summaries, edges, {{0, "object"}});

        auto shuffled = summaries;
        std::vector<std::size_t> to(count);
        for (int index = 0; index < count; ++index) to[index] = index;
        std::shuffle(to.begin(), to.end(), random);
        for (int index = 0; index < count; ++index) {
            shuffled[to[index]] = summaries[index];
            std::shuffle(shuffled[to[index]].accesses.begin(), shuffled[to[index]].accesses.end(),
                         random);
        }
        auto moved = edges;
        for (auto& edge : moved) {
            edge.caller = to[edge.caller];
            edge.callee = to[edge.callee];
        }
        std::shuffle(moved.begin(), moved.end(), random);
        const auto other = solve_summaries(shuffled, moved, {{to[0], "object"}});
        require(facts(summaries, base.roots[0]) == facts(shuffled, other.roots[0]),
                "derived facts depend on input order (round " + std::to_string(round) + ")");
        require(base.roots[0].withheld_components.size() ==
                    other.roots[0].withheld_components.size() &&
                base.components.size() == other.components.size(),
                "components depend on input order");
        for (std::size_t index = 0; index < base.components.size(); ++index) {
            require(base.components[index].consistent == other.components[index].consistent,
                    "component consistency depends on input order");
            for (std::size_t member = 0; member < base.components[index].summaries.size(); ++member) {
                require(summaries[base.components[index].summaries[member]].id ==
                            shuffled[other.components[index].summaries[member]].id,
                        "component members depend on input order");
            }
        }
    }
}

void deep_graphs() {
    constexpr std::size_t count = 200'000;
    std::vector<ParameterSummary> summaries;
    std::vector<ForwardingEdge> edges;
    for (std::size_t index = 0; index < count; ++index) {
        summaries.push_back({"n" + std::to_string(index), {access(0, 1, "e" + std::to_string(index))}});
        if (index + 1 < count) edges.push_back({index, index + 1, 1, "c"});
    }
    SummarySolveOptions options;
    options.maximum_states = count;
    options.maximum_derived = count;
    const auto chain = solve_summaries(summaries, edges, {{0, "object"}}, options);
    require(chain.roots[0].complete() && chain.roots[0].states.size() == count,
            "deep chain not solved");
    require(chain.roots[0].layout->minimum_extent == count, "deep chain extent wrong");

    // One cycle through every summary: Tarjan must not recurse per member.
    edges.push_back({count - 1, 0, -static_cast<std::int64_t>(count - 1), "back"});
    const auto ring = solve_summaries(summaries, edges, {{0, "object"}}, options);
    require(ring.components.size() == 1 && ring.components[0].summaries.size() == count &&
                ring.components[0].consistent,
            "deep zero-sum ring not one consistent component");
    edges.back().offset = 0;
    const auto drift = solve_summaries(summaries, edges, {{0, "object"}}, options);
    require(!drift.components.at(0).consistent && drift.roots[0].states.size() == 1,
            "deep drifting ring must withhold its edges");
}

}  // namespace

int main() {
    const std::vector<std::pair<const char*, void (*)()>> tests = {
        {"chain_shift_and_interior_pointer", chain_shift_and_interior_pointer},
        {"diamonds", diamonds},
        {"consistent_cycles", consistent_cycles},
        {"inconsistent_cycles_withhold", inconsistent_cycles_withhold},
        {"overflow_and_rejection", overflow_and_rejection},
        {"limits_fail_closed", limits_fail_closed},
        {"invalid_input", invalid_input},
        {"typed_views_cross_calls", typed_views_cross_calls},
        {"duplicates_and_roots", duplicates_and_roots},
        {"permutation_stability", permutation_stability},
        {"deep_graphs", deep_graphs},
    };
    for (const auto& [name, test] : tests) {
        try {
            test();
        } catch (const std::exception& error) {
            std::cerr << name << ": " << error.what() << '\n';
            return 1;
        }
    }
    std::cout << "summary solver: " << tests.size() << " test cases passed\n";
    return 0;
}
