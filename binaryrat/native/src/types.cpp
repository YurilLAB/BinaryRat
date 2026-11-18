// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

#include "binaryrat/types.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <utility>

namespace binaryrat::types {
namespace {

struct FieldEvidence {
    std::set<std::string> evidence_ids;
    std::set<std::uint64_t> strides;
    std::map<StorageView, std::set<std::string>> typed_views;
};

using FieldKey = std::pair<std::uint64_t, std::uint64_t>;
using FieldMap = std::map<FieldKey, FieldEvidence>;

std::optional<RejectionReason> validate(const AccessObservation& observation,
                                      LayoutRecoveryOptions options) {
    if (observation.object_id.empty()) {
        return RejectionReason::empty_object_id;
    }
    if (observation.evidence_id.empty()) {
        return RejectionReason::empty_evidence_id;
    }
    if (!observation.object_start_known) {
        return RejectionReason::unknown_object_start;
    }
    if (observation.offset < 0) {
        return RejectionReason::negative_offset;
    }
    if (observation.width == 0) {
        return RejectionReason::zero_width;
    }
    if (observation.stride && *observation.stride == 0) {
        return RejectionReason::zero_stride;
    }
    const auto offset = static_cast<std::uint64_t>(observation.offset);
    if (observation.width > std::numeric_limits<std::uint64_t>::max() - offset) {
        return RejectionReason::extent_overflow;
    }
    if (offset + observation.width > options.maximum_extent) {
        return RejectionReason::extent_limit;
    }
    return std::nullopt;
}

bool supported_view(const AccessObservation& observation) {
    if (!observation.storage_view || observation.stride) {
        return false;
    }
    const auto width = observation.width;
    switch (*observation.storage_view) {
        case StorageView::integer:
            return width == 1 || width == 2 || width == 4 || width == 8;
        case StorageView::floating_point:
            return width == 4 || width == 8;
    }
    return false;
}

void append_union_candidate(RecoveredLayout& layout, std::uint64_t offset,
                            std::vector<UnionView> views) {
    std::map<std::string, std::size_t> occurrences;
    for (const auto& view : views) {
        for (const auto& id : view.evidence_ids) {
            ++occurrences[id];
        }
    }
    for (auto& view : views) {
        // Conflicting labels invalidate that evidence, even when other
        // independent loads support the same shared storage.
        std::erase_if(view.evidence_ids, [&](const auto& id) { return occurrences.at(id) > 1; });
    }
    std::erase_if(views, [](const auto& view) { return view.evidence_ids.empty(); });

    std::size_t evidence_count = 0;
    bool has_integer = false;
    bool has_float = false;
    for (const auto& view : views) {
        has_integer |= view.kind == StorageView::integer;
        has_float |= view.kind == StorageView::floating_point;
        evidence_count += view.evidence_ids.size();
    }
    if (has_integer && has_float) {
        const auto support = static_cast<double>(evidence_count);
        layout.union_candidates.push_back({offset, std::move(views), support / (support + 1.0)});
    }
}

}  // namespace

std::string_view to_string(StorageView view) noexcept {
    switch (view) {
        case StorageView::integer:
            return "integer";
        case StorageView::floating_point:
            return "floating_point";
    }
    return "unknown";
}

std::string_view to_string(RejectionReason reason) noexcept {
    switch (reason) {
        case RejectionReason::empty_object_id:
            return "empty object ID";
        case RejectionReason::empty_evidence_id:
            return "empty evidence ID";
        case RejectionReason::unknown_object_start:
            return "unknown object start or interior pointer";
        case RejectionReason::negative_offset:
            return "negative offset";
        case RejectionReason::zero_width:
            return "zero access width";
        case RejectionReason::zero_stride:
            return "zero stride";
        case RejectionReason::extent_overflow:
            return "offset plus width overflows";
        case RejectionReason::extent_limit:
            return "object extent exceeds configured limit";
    }
    return "unknown rejection reason";
}

LayoutRecoveryResult recover_layouts(
    const std::vector<AccessObservation>& observations,
    LayoutRecoveryOptions options) {
    LayoutRecoveryResult result;
    std::map<std::string, FieldMap> objects;

    for (std::size_t index = 0; index < observations.size(); ++index) {
        const auto& observation = observations[index];
        if (const auto reason = validate(observation, options)) {
            result.rejected.push_back({index, *reason});
            continue;
        }
        auto& evidence = objects[observation.object_id][{
            static_cast<std::uint64_t>(observation.offset), observation.width}];
        evidence.evidence_ids.insert(observation.evidence_id);
        if (observation.stride) {
            evidence.strides.insert(*observation.stride);
        }
        if (supported_view(observation)) {
            evidence.typed_views[*observation.storage_view].insert(observation.evidence_id);
        }
    }

    for (const auto& [object_id, field_map] : objects) {
        RecoveredLayout layout;
        layout.object_id = object_id;
        layout.fields.reserve(field_map.size());
        std::map<std::uint64_t, std::vector<UnionView>> union_views;
        for (const auto& [key, evidence] : field_map) {
            RecoveredField field;
            field.offset = key.first;
            field.width = key.second;
            field.evidence_ids.assign(evidence.evidence_ids.begin(),
                                      evidence.evidence_ids.end());
            const auto support = static_cast<double>(field.evidence_count());
            field.evidence_strength = support / (support + 1.0);
            field.stride_conflict = evidence.strides.size() > 1;
            if (evidence.strides.size() == 1) {
                field.stride = *evidence.strides.begin();
            }
            field.stride_overlaps_access =
                !evidence.strides.empty() &&
                *evidence.strides.begin() < field.width;
            layout.has_stride_conflicts |= field.stride_conflict;
            layout.has_overlapping_stride |= field.stride_overlaps_access;
            layout.minimum_extent =
                std::max(layout.minimum_extent, field.offset + field.width);
            for (const auto& [kind, evidence_ids] : evidence.typed_views) {
                union_views[field.offset].push_back(
                    {kind, field.width, {evidence_ids.begin(), evidence_ids.end()}});
            }
            layout.fields.push_back(std::move(field));
        }
        for (auto& [offset, views] : union_views) {
            append_union_candidate(layout, offset, std::move(views));
        }

        // Sorted intervals allow marking every interval that overlaps another
        // in linear time: compare with the greatest earlier end and the next
        // interval's start. Adjoining half-open intervals do not overlap.
        std::uint64_t earlier_maximum_end = 0;
        for (std::size_t index = 0; index < layout.fields.size(); ++index) {
            auto& field = layout.fields[index];
            const auto end = field.offset + field.width;
            const bool overlaps_earlier = field.offset < earlier_maximum_end;
            const bool overlaps_later =
                index + 1 < layout.fields.size() &&
                layout.fields[index + 1].offset < end;
            field.overlaps_other_fields = overlaps_earlier || overlaps_later;
            layout.has_overlaps |= field.overlaps_other_fields;
            earlier_maximum_end = std::max(earlier_maximum_end, end);
        }
        result.layouts.push_back(std::move(layout));
    }
    return result;
}

}  // namespace binaryrat::types
