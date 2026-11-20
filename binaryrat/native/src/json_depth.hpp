// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <string_view>

namespace binaryrat::detail {

// Copying, comparing and serializing a JSON value recurse once per nesting level,
// so text from outside the process is bounded before it is parsed. No request or
// cache record the bridge or the Python client writes nests deeper than seven.
constexpr std::size_t maximum_json_depth = 64;

// True when the arrays and objects in `text` nest deeper than `limit`. Brackets
// inside strings do not count. Text that is not JSON may be reported either way;
// the parser rejects it afterwards.
[[nodiscard]] constexpr bool json_nests_deeper_than(std::string_view text, std::size_t limit) noexcept {
    std::size_t depth = 0;
    bool in_string = false;
    for (std::size_t index = 0; index < text.size(); ++index) {
        const char c = text[index];
        if (in_string) {
            if (c == '\\') ++index;
            else if (c == '"') in_string = false;
        } else if (c == '"') {
            in_string = true;
        } else if (c == '[' || c == '{') {
            if (++depth > limit) return true;
        } else if ((c == ']' || c == '}') && depth > 0) {
            --depth;
        }
    }
    return false;
}

} // namespace binaryrat::detail
