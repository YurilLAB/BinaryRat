// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binaryrat::types {

// Preliminary layout evidence, not a recovered source-language type. An access
// must be relative to a separately established object start; an interior or
// unknown pointer base is insufficient evidence for a layout.
struct AccessObservation {
    std::string object_id;
    std::int64_t offset{0};
    std::uint64_t width{0};
    std::optional<std::uint64_t> stride;
    std::string evidence_id;
    bool object_start_known{false};
};

struct LayoutRecoveryOptions {
    // Maximum permitted one-past-the-end offset, in bytes. No storage is
    // allocated in proportion to this value. A zero limit rejects all accesses.
    std::uint64_t maximum_extent{std::uint64_t{1} << 32};
};

enum class RejectionReason {
    empty_object_id,
    empty_evidence_id,
    unknown_object_start,
    negative_offset,
    zero_width,
    zero_stride,
    extent_overflow,
    extent_limit,
};

[[nodiscard]] std::string_view to_string(RejectionReason reason) noexcept;

struct RejectedObservation {
    std::size_t observation_index{0};
    RejectionReason reason{RejectionReason::empty_object_id};
};

struct RecoveredField {
    std::uint64_t offset{0};
    std::uint64_t width{0};
    // An observed affine stride, not proof of an array or its element count.
    // Conflicting strides are retained as ambiguity instead of selecting one.
    std::optional<std::uint64_t> stride;
    std::vector<std::string> evidence_ids;
    // Uncalibrated support score n/(n+1), where n counts distinct evidence IDs.
    // This is deliberately not named confidence or interpreted as probability.
    double evidence_strength{0.0};
    bool overlaps_other_fields{false};
    bool stride_conflict{false};
    bool stride_overlaps_access{false};

    [[nodiscard]] std::size_t evidence_count() const noexcept {
        return evidence_ids.size();
    }
};

struct RecoveredLayout {
    std::string object_id;
    // Exact (offset, width) observations are grouped. Gaps are left unknown;
    // overlapping fields are alternatives, never automatically made a union.
    std::vector<RecoveredField> fields;
    // A lower bound only: neither an exact object size nor an array bound.
    std::uint64_t minimum_extent{0};
    bool has_overlaps{false};
    bool has_stride_conflicts{false};
    bool has_overlapping_stride{false};
};

struct LayoutRecoveryResult {
    // Deterministic ordering: object ID, then field offset and width; evidence
    // IDs are sorted. Rejections retain original observation order and indices.
    std::vector<RecoveredLayout> layouts;
    std::vector<RejectedObservation> rejected;
};

// Pure evidence aggregation. Does not mutate observations, inspect a binary,
// infer class/union semantics, or write to a Ghidra program database.
[[nodiscard]] LayoutRecoveryResult recover_layouts(
    const std::vector<AccessObservation>& observations,
    LayoutRecoveryOptions options = {});

}  // namespace binaryrat::types
