// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace binaryrat::strings {

// One constant value stored to a stack slot, as the bytes land in memory.
struct StackWrite {
    std::int64_t offset = 0;          // stack offset of the first byte
    std::vector<std::uint8_t> bytes;  // 1 to maximum_write_bytes bytes, lowest address first
    std::uint64_t order = 0;          // program order; a later write replaces earlier bytes
};

enum class Encoding { ascii, utf16le };

// Text assembled from the final bytes of one group of writes.
struct StackString {
    std::int64_t offset = 0;           // first byte of the text
    std::uint64_t byte_length = 0;     // bytes of text, not counting a terminator
    Encoding encoding = Encoding::ascii;
    std::string text;                  // the characters, all printable ASCII, tab, newline or CR
    bool terminated = false;           // a NUL terminator follows inside the written bytes
    std::vector<std::uint64_t> orders; // writes that supplied the text or terminator, ascending
};

struct StackStringOptions {
    std::size_t minimum_length = 4;  // characters; 1 to 64
    std::size_t maximum_writes = 65'536;
    std::size_t maximum_bytes = 1 << 20;  // distinct stack bytes
};

inline constexpr std::size_t maximum_write_bytes = 64;
inline constexpr std::size_t maximum_minimum_length = 64;

// Applies the writes in ascending order (ties keep input order), so each stack byte holds
// its last value, then splits the written bytes into contiguous runs. Each run is scanned
// from its lowest offset: at each position a UTF-16LE string (printable ASCII code units)
// of at least minimum_length characters is taken first, else an ASCII string of at least
// minimum_length bytes; a taken string also consumes its terminator. Throws
// std::invalid_argument when a limit or an offset range is exceeded.
std::vector<StackString> recover_stack_strings(const std::vector<StackWrite>& writes,
                                               const StackStringOptions& options = {});

[[nodiscard]] const char* encoding_name(Encoding encoding) noexcept;

}  // namespace binaryrat::strings
