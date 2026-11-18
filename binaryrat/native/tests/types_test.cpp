// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

#include "binaryrat/types.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace binaryrat::types;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

AccessObservation access(std::string object, std::int64_t offset,
                         std::uint64_t width, std::string evidence,
                         std::optional<std::uint64_t> stride = std::nullopt) {
    return {std::move(object), offset, width, stride, std::move(evidence), true};
}

void gaps_and_objects() {
    const auto result = recover_layouts({access("z", 4, 2, "z-access"),
                                         access("a", 16, 8, "a-tail"),
                                         access("a", 0, 4, "a-head")});
    require(result.rejected.empty(), "valid accesses rejected");
    require(result.layouts.size() == 2, "different objects were merged");
    const auto& layout = result.layouts[0];
    require(layout.object_id == "a", "objects not sorted deterministically");
    require(layout.fields.size() == 2, "gap invented a field");
    require(layout.fields[0].offset == 0 && layout.fields[1].offset == 16,
            "field offsets not preserved or sorted");
    require(layout.minimum_extent == 24, "incorrect minimum extent");
    require(!layout.has_overlaps, "gap reported as overlap");
    require(result.layouts[1].minimum_extent == 6,
            "extent leaked across objects");
}

void deduplicate_evidence() {
    const auto result = recover_layouts({access("obj", 0, 4, "b"),
                                         access("obj", 0, 4, "a"),
                                         access("obj", 0, 4, "a")});
    const auto& field = result.layouts.at(0).fields.at(0);
    require(field.evidence_count() == 2, "duplicate evidence inflated support");
    require(field.evidence_ids == std::vector<std::string>({"a", "b"}),
            "evidence IDs not retained and sorted");
    require(std::abs(field.evidence_strength - 2.0 / 3.0) < 1e-12,
            "support score does not reflect distinct evidence");
}

void overlapping_alternatives() {
    const auto result = recover_layouts({access("obj", 0, 16, "wide"),
                                         access("obj", 4, 4, "inside"),
                                         access("obj", 12, 4, "late-inside"),
                                         access("obj", 16, 4, "adjacent")});
    const auto& layout = result.layouts.at(0);
    require(layout.has_overlaps, "nested overlaps not found");
    require(layout.fields.size() == 4, "overlap collapsed into a forced union");
    require(layout.fields[0].overlaps_other_fields &&
                layout.fields[1].overlaps_other_fields &&
                layout.fields[2].overlaps_other_fields,
            "not every overlapping alternative marked");
    require(!layout.fields[3].overlaps_other_fields,
            "adjoining half-open intervals incorrectly overlap");
}

void same_offset_different_widths() {
    const auto result = recover_layouts({access("obj", 0, 8, "wide"),
                                         access("obj", 0, 4, "narrow")});
    const auto& layout = result.layouts.at(0);
    require(layout.fields.size() == 2, "different access widths were unified");
    require(layout.fields[0].width == 4 && layout.fields[1].width == 8,
            "width ordering or preservation failed");
    require(layout.fields[0].overlaps_other_fields &&
                layout.fields[1].overlaps_other_fields,
            "equal-start overlaps not marked");
    require(layout.union_candidates.empty(), "overlap alone invented a union candidate");
}

void typed_union_candidates() {
    auto integer = access("object", 24, 4, "integer-use");
    integer.storage_view = StorageView::integer;
    auto floating = access("object", 24, 8, "float-use");
    floating.storage_view = StorageView::floating_point;
    const auto recovered = recover_layouts({floating, integer, floating});
    const auto& layout = recovered.layouts.at(0);
    require(layout.fields.size() == 2, "typed evidence replaced the layout fields");
    const auto& candidate = layout.union_candidates.at(0);
    require(layout.union_candidates.size() == 1 && candidate.offset == 24,
            "same-slot typed loads did not create exactly one candidate");
    require(candidate.views.size() == 2 &&
                candidate.views[0].kind == StorageView::integer &&
                candidate.views[0].width == 4 &&
                candidate.views[0].evidence_ids == std::vector<std::string>{"integer-use"} &&
                candidate.views[1].kind == StorageView::floating_point &&
                candidate.views[1].width == 8 &&
                candidate.views[1].evidence_ids == std::vector<std::string>{"float-use"} &&
                std::abs(candidate.evidence_strength - 2.0 / 3.0) < 1e-12,
            "union view order or distinct support incorrect");

    floating.width = integer.width;
    auto same_width = recover_layouts({integer, floating});
    require(!same_width.layouts[0].has_overlaps &&
                same_width.layouts[0].union_candidates.size() == 1,
            "a shared slot of equal width lost its separate typed interpretations");
    floating.evidence_id = integer.evidence_id;
    require(recover_layouts({integer, floating}).layouts[0].union_candidates.empty(),
            "two labels for one access supplied independent typed evidence");
    auto another_integer = integer;
    another_integer.evidence_id = "another-int";
    auto another_float = floating;
    another_float.evidence_id = "another-float";
    const auto with_conflict = recover_layouts({integer, floating, another_integer, another_float});
    const auto& resolved = with_conflict.layouts[0].union_candidates.at(0);
    require(resolved.views[0].evidence_ids == std::vector<std::string>{"another-int"} &&
                resolved.views[1].evidence_ids == std::vector<std::string>{"another-float"},
            "conflicting evidence was retained alongside independent loads");
    floating.evidence_id = "other";
    floating.offset += 1;
    require(recover_layouts({integer, floating}).layouts[0].union_candidates.empty(),
            "overlap with a different start created a candidate");
    floating.offset = integer.offset;
    floating.stride = 8;
    require(recover_layouts({integer, floating}).layouts[0].union_candidates.empty(),
            "variable-offset evidence created an exact union candidate");
    floating.stride.reset();
    floating.width = 2;
    require(recover_layouts({integer, floating}).layouts[0].union_candidates.empty(),
            "an unsupported floating width created a candidate");
}

void stride_is_evidence_only() {
    const auto result = recover_layouts({access("obj", 0, 4, "a", 16),
                                         access("obj", 0, 4, "b", 16),
                                         access("obj", 0, 4, "c")});
    const auto& layout = result.layouts.at(0);
    require(layout.fields.at(0).stride == 16, "consistent stride discarded");
    require(!layout.has_stride_conflicts, "consistent stride is a conflict");
    require(layout.minimum_extent == 4 && layout.fields.size() == 1,
            "stride invented array bounds or additional fields");
}

void conflicting_and_overlapping_strides() {
    const auto result = recover_layouts({access("obj", 0, 8, "a", 4),
                                         access("obj", 0, 8, "b", 16)});
    const auto& layout = result.layouts.at(0);
    const auto& field = layout.fields.at(0);
    require(!field.stride, "conflicting strides selected arbitrarily");
    require(field.stride_conflict && layout.has_stride_conflicts,
            "stride conflict not exposed");
    require(field.stride_overlaps_access && layout.has_overlapping_stride,
            "overlapping stride not exposed as ambiguity");
    require(field.evidence_count() == 2, "stride conflict lost evidence");
}

void abstain_without_object_origin() {
    auto unknown = access("unknown", 0, 4, "a");
    unknown.object_start_known = false;
    const auto result = recover_layouts({unknown,
                                         access("interior", -4, 4, "b"),
                                         access("valid", 0, 4, "c")});
    require(result.layouts.size() == 1 &&
                result.layouts[0].object_id == "valid",
            "unknown/interior pointer produced a layout");
    require(result.rejected.size() == 2, "abstention diagnostics missing");
    require(result.rejected[0].observation_index == 0 &&
                result.rejected[0].reason == RejectionReason::unknown_object_start,
            "unknown origin diagnostic incorrect");
    require(result.rejected[1].observation_index == 1 &&
                result.rejected[1].reason == RejectionReason::negative_offset,
            "negative offset diagnostic incorrect");
}

void invalid_observations() {
    const auto result = recover_layouts({access("", 0, 4, "a"),
                                         access("obj", 0, 4, ""),
                                         access("obj", 0, 0, "b"),
                                         access("obj", 0, 4, "c", 0)});
    require(result.layouts.empty(), "invalid accesses created an object");
    const std::vector<RejectionReason> expected{
        RejectionReason::empty_object_id, RejectionReason::empty_evidence_id,
        RejectionReason::zero_width, RejectionReason::zero_stride};
    require(result.rejected.size() == expected.size(), "missing invalid input");
    for (std::size_t index = 0; index < expected.size(); ++index) {
        require(result.rejected[index].observation_index == index &&
                    result.rejected[index].reason == expected[index],
                "wrong invalid-input diagnostic");
        require(!to_string(expected[index]).empty(), "empty diagnostic string");
    }
}

void checked_arithmetic_and_limits() {
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    const auto overflow = recover_layouts({access("obj", 1, maximum, "a")},
                                          {maximum});
    require(overflow.layouts.empty() && overflow.rejected.size() == 1 &&
                overflow.rejected[0].reason == RejectionReason::extent_overflow,
            "unsigned extent overflow not rejected");

    const auto bounded = recover_layouts({access("ok", 8, 8, "a"),
                                          access("too-big", 8, 9, "b")},
                                         {16});
    require(bounded.layouts.size() == 1 &&
                bounded.layouts[0].minimum_extent == 16,
            "exact boundary not accepted");
    require(bounded.rejected.size() == 1 &&
                bounded.rejected[0].reason == RejectionReason::extent_limit,
            "configured extent limit not enforced");

    const auto huge = recover_layouts(
        {access("huge", std::numeric_limits<std::int64_t>::max(),
                std::uint64_t{1} << 63, "a")},
        {maximum});
    require(huge.layouts.size() == 1 &&
                huge.layouts[0].minimum_extent == maximum,
            "large representable extent mishandled");
    const auto zero = recover_layouts({access("obj", 0, 1, "a")}, {0});
    require(zero.layouts.empty() && zero.rejected.size() == 1,
            "zero extent limit not enforced");
}

void empty_and_permutation_stability() {
    require(recover_layouts({}).layouts.empty(), "empty input created a layout");
    std::vector<AccessObservation> observations{
        access("obj", 4, 4, "b", 8), access("obj", 0, 8, "c"),
        access("obj", 4, 4, "a", 16)};
    const auto first = recover_layouts(observations);
    std::reverse(observations.begin(), observations.end());
    const auto second = recover_layouts(observations);
    const auto& left = first.layouts.at(0);
    const auto& right = second.layouts.at(0);
    require(left.minimum_extent == right.minimum_extent &&
                left.fields.size() == right.fields.size(),
            "permutation changed layout shape");
    for (std::size_t index = 0; index < left.fields.size(); ++index) {
        const auto& a = left.fields[index];
        const auto& b = right.fields[index];
        require(a.offset == b.offset && a.width == b.width &&
                    a.stride == b.stride && a.evidence_ids == b.evidence_ids &&
                    a.evidence_strength == b.evidence_strength &&
                    a.overlaps_other_fields == b.overlaps_other_fields &&
                    a.stride_conflict == b.stride_conflict,
                "permutation changed recovered field evidence");
    }
}

}  // namespace

int main() {
    try {
        gaps_and_objects();
        deduplicate_evidence();
        overlapping_alternatives();
        same_offset_different_widths();
        typed_union_candidates();
        stride_is_evidence_only();
        conflicting_and_overlapping_strides();
        abstain_without_object_origin();
        invalid_observations();
        checked_arithmetic_and_limits();
        empty_and_permutation_stability();
        std::cout << "type layout recovery: 11 test cases passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "type layout recovery test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
