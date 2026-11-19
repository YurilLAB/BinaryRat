// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

#include "binaryrat/summaries.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <numeric>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace binaryrat::types {
namespace {

constexpr std::size_t unvisited = std::numeric_limits<std::size_t>::max();

std::optional<std::int64_t> checked_add(std::int64_t left, std::int64_t right) {
    if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) {
        return std::nullopt;
    }
    return left + right;
}

struct Graph {
    // Unique edges in canonical order, grouped by caller.
    std::vector<std::vector<std::size_t>> adjacency;
    // Summary access indices in canonical order.
    std::vector<std::vector<std::size_t>> accesses;
};

// Orders by IDs and values rather than input positions, so permuting the input
// changes only which equal duplicate is named, never what is reached.
Graph canonical_graph(const std::vector<ParameterSummary>& summaries,
                      const std::vector<ForwardingEdge>& edges) {
    Graph graph;
    graph.adjacency.resize(summaries.size());
    graph.accesses.resize(summaries.size());

    std::vector<std::size_t> order(edges.size());
    std::iota(order.begin(), order.end(), std::size_t{0});
    const auto edge_key = [&](std::size_t index) {
        const auto& edge = edges[index];
        return std::tie(summaries[edge.caller].id, summaries[edge.callee].id, edge.offset,
                        edge.evidence_id);
    };
    std::sort(order.begin(), order.end(), [&](std::size_t left, std::size_t right) {
        const auto left_key = edge_key(left);
        const auto right_key = edge_key(right);
        return left_key != right_key ? left_key < right_key : left < right;
    });
    for (std::size_t position = 0; position < order.size(); ++position) {
        const auto index = order[position];
        if (position > 0 && edge_key(order[position - 1]) == edge_key(index)) {
            continue;
        }
        graph.adjacency[edges[index].caller].push_back(index);
    }

    for (std::size_t summary = 0; summary < summaries.size(); ++summary) {
        const auto& list = summaries[summary].accesses;
        auto& indices = graph.accesses[summary];
        indices.resize(list.size());
        std::iota(indices.begin(), indices.end(), std::size_t{0});
        std::sort(indices.begin(), indices.end(), [&](std::size_t left, std::size_t right) {
            const auto& a = list[left];
            const auto& b = list[right];
            const auto a_view = a.storage_view ? static_cast<int>(*a.storage_view) + 1 : 0;
            const auto b_view = b.storage_view ? static_cast<int>(*b.storage_view) + 1 : 0;
            const auto a_key = std::tie(a.offset, a.width, a.evidence_id, a_view);
            const auto b_key = std::tie(b.offset, b.width, b.evidence_id, b_view);
            return a_key != b_key ? a_key < b_key : left < right;
        });
    }
    return graph;
}

// Iterative Tarjan: deep call chains must not exhaust the native stack.
std::vector<std::vector<std::size_t>> strongly_connected(
    const std::vector<ForwardingEdge>& edges, const Graph& graph) {
    const auto count = graph.adjacency.size();
    std::vector<std::size_t> index(count, unvisited);
    std::vector<std::size_t> low(count, 0);
    std::vector<bool> on_stack(count, false);
    std::vector<std::size_t> stack;
    std::vector<std::vector<std::size_t>> components;
    std::size_t next_index = 0;

    struct Frame {
        std::size_t node;
        std::size_t next;
    };
    std::vector<Frame> frames;
    for (std::size_t start = 0; start < count; ++start) {
        if (index[start] != unvisited) {
            continue;
        }
        index[start] = low[start] = next_index++;
        stack.push_back(start);
        on_stack[start] = true;
        frames.push_back({start, 0});
        while (!frames.empty()) {
            const auto node = frames.back().node;
            const auto& adjacent = graph.adjacency[node];
            if (frames.back().next < adjacent.size()) {
                const auto target = edges[adjacent[frames.back().next++]].callee;
                if (index[target] == unvisited) {
                    index[target] = low[target] = next_index++;
                    stack.push_back(target);
                    on_stack[target] = true;
                    frames.push_back({target, 0});
                } else if (on_stack[target]) {
                    low[node] = std::min(low[node], index[target]);
                }
                continue;
            }
            frames.pop_back();
            if (!frames.empty()) {
                auto& parent = low[frames.back().node];
                parent = std::min(parent, low[node]);
            }
            if (low[node] == index[node]) {
                std::vector<std::size_t> component;
                std::size_t member;
                do {
                    member = stack.back();
                    stack.pop_back();
                    on_stack[member] = false;
                    component.push_back(member);
                } while (member != node);
                components.push_back(std::move(component));
            }
        }
    }
    return components;
}

// A component is consistent when one position per member satisfies every
// internal edge: position(callee) == position(caller) + offset.
bool consistent_offsets(const std::vector<std::size_t>& members,
                        const std::vector<std::size_t>& component_of, std::size_t component,
                        const std::vector<ForwardingEdge>& edges, const Graph& graph) {
    std::map<std::size_t, std::int64_t> position;
    std::vector<std::size_t> queue{members.front()};
    position[members.front()] = 0;
    for (std::size_t head = 0; head < queue.size(); ++head) {
        const auto node = queue[head];
        for (const auto edge_index : graph.adjacency[node]) {
            const auto& edge = edges[edge_index];
            if (component_of[edge.callee] != component) {
                continue;
            }
            const auto expected = checked_add(position.at(node), edge.offset);
            if (!expected) {
                return false;
            }
            const auto [found, inserted] = position.try_emplace(edge.callee, *expected);
            if (inserted) {
                queue.push_back(edge.callee);
            } else if (found->second != *expected) {
                return false;
            }
        }
    }
    return true;
}

// A root over a limit reports only its status: a partial search is never shown.
RootSolution limited(RootStatus status) {
    RootSolution solution;
    solution.status = status;
    return solution;
}

RootSolution solve_root(const std::vector<ParameterSummary>& summaries,
                        const std::vector<ForwardingEdge>& edges, const Graph& graph,
                        const std::vector<std::optional<std::size_t>>& withheld_by,
                        const SolveRoot& root, const SummarySolveOptions& options) {
    RootSolution solution;
    if (options.maximum_states == 0) {
        return limited(RootStatus::state_limit);
    }
    std::map<std::pair<std::size_t, std::int64_t>, std::size_t> seen;
    std::set<std::size_t> withheld;
    auto& states = solution.states;
    states.push_back({root.summary, 0, 0, std::nullopt, std::nullopt});
    seen.emplace(std::pair{root.summary, std::int64_t{0}}, 0);
    // Breadth-first over (summary, offset): the first path to each state is a
    // shortest one, and a consistent cycle returns to a state already seen.
    for (std::size_t current = 0; current < states.size(); ++current) {
        const auto state = states[current];
        for (const auto edge_index : graph.adjacency[state.summary]) {
            if (const auto component = withheld_by[edge_index]) {
                withheld.insert(*component);
                continue;
            }
            const auto& edge = edges[edge_index];
            const auto offset = checked_add(state.offset, edge.offset);
            if (!offset) {
                ++solution.overflowed;
                continue;
            }
            if (!seen.try_emplace(std::pair{edge.callee, *offset}, states.size()).second) {
                continue;
            }
            if (states.size() >= options.maximum_states) {
                return limited(RootStatus::state_limit);
            }
            states.push_back({edge.callee, *offset, state.hops + 1, edge_index, current});
        }
    }

    std::vector<AccessObservation> observations;
    for (std::size_t index = 0; index < states.size(); ++index) {
        const auto& state = states[index];
        for (const auto access_index : graph.accesses[state.summary]) {
            const auto& access = summaries[state.summary].accesses[access_index];
            const auto offset = checked_add(state.offset, access.offset);
            if (!offset) {
                ++solution.overflowed;
                continue;
            }
            if (solution.derived.size() >= options.maximum_derived) {
                return limited(RootStatus::derived_limit);
            }
            solution.derived.push_back({index, access_index, *offset});
            observations.push_back({root.object_id, *offset, access.width, std::nullopt,
                                    access.evidence_id, true, access.storage_view});
        }
    }
    auto recovered = recover_layouts(observations, {options.maximum_extent});
    if (!recovered.layouts.empty()) {
        solution.layout = std::move(recovered.layouts.front());
    }
    solution.rejected = std::move(recovered.rejected);
    solution.withheld_components.assign(withheld.begin(), withheld.end());
    return solution;
}

}  // namespace

std::string_view to_string(RootStatus status) noexcept {
    switch (status) {
        case RootStatus::solved:
            return "solved";
        case RootStatus::state_limit:
            return "state_limit";
        case RootStatus::derived_limit:
            return "derived_limit";
    }
    return "unknown";
}

SummarySolution solve_summaries(const std::vector<ParameterSummary>& summaries,
                                const std::vector<ForwardingEdge>& edges,
                                const std::vector<SolveRoot>& roots,
                                SummarySolveOptions options) {
    std::set<std::string_view> ids;
    for (const auto& summary : summaries) {
        if (summary.id.empty()) {
            throw std::invalid_argument("summary IDs must be nonempty");
        }
        if (!ids.insert(summary.id).second) {
            throw std::invalid_argument("duplicate summary ID: " + summary.id);
        }
    }
    for (const auto& edge : edges) {
        if (edge.caller >= summaries.size() || edge.callee >= summaries.size()) {
            throw std::invalid_argument("forwarding edge names an unknown summary");
        }
    }
    for (const auto& root : roots) {
        if (root.summary >= summaries.size()) {
            throw std::invalid_argument("root names an unknown summary");
        }
    }

    const auto graph = canonical_graph(summaries, edges);
    auto found = strongly_connected(edges, graph);
    std::vector<std::size_t> component_of(summaries.size(), 0);
    for (std::size_t component = 0; component < found.size(); ++component) {
        for (const auto member : found[component]) {
            component_of[member] = component;
        }
    }

    SummarySolution solution;
    std::vector<std::pair<std::size_t, std::vector<std::size_t>>> nontrivial;
    for (std::size_t component = 0; component < found.size(); ++component) {
        auto& members = found[component];
        std::sort(members.begin(), members.end(), [&](std::size_t left, std::size_t right) {
            return summaries[left].id < summaries[right].id;
        });
        const bool self_call = members.size() == 1 &&
            std::any_of(graph.adjacency[members.front()].begin(),
                        graph.adjacency[members.front()].end(), [&](std::size_t edge) {
                            return edges[edge].callee == members.front();
                        });
        if (members.size() > 1 || self_call) {
            nontrivial.emplace_back(component, members);
        }
    }
    std::sort(nontrivial.begin(), nontrivial.end(), [&](const auto& left, const auto& right) {
        return summaries[left.second.front()].id < summaries[right.second.front()].id;
    });

    std::vector<std::optional<std::size_t>> inconsistent_output(found.size());
    for (const auto& [component, members] : nontrivial) {
        CallComponent output;
        output.summaries = members;
        output.consistent = consistent_offsets(members, component_of, component, edges, graph);
        if (!output.consistent) {
            inconsistent_output[component] = solution.components.size();
        }
        solution.components.push_back(std::move(output));
    }
    // One pass: every internal edge of an inconsistent component is withheld,
    // duplicates included, so the list names each input edge it covers.
    std::vector<std::optional<std::size_t>> withheld_by(edges.size());
    for (std::size_t edge = 0; edge < edges.size(); ++edge) {
        const auto component = component_of[edges[edge].caller];
        if (component == component_of[edges[edge].callee] && inconsistent_output[component]) {
            withheld_by[edge] = inconsistent_output[component];
            solution.components[*inconsistent_output[component]].withheld_edges.push_back(edge);
        }
    }

    solution.roots.reserve(roots.size());
    for (const auto& root : roots) {
        solution.roots.push_back(solve_root(summaries, edges, graph, withheld_by, root, options));
    }
    return solution;
}

}  // namespace binaryrat::types
