// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0

#include "binaryrat/strings.hpp"

#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace binaryrat::strings;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

StackWrite write(std::int64_t offset, const std::string& bytes, std::uint64_t order) {
    return {offset, std::vector<std::uint8_t>(bytes.begin(), bytes.end()), order};
}

template <typename Call>
void rejects(Call call, const std::string& message) {
    try {
        call();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error("accepted " + message);
}

// mov dword [rbp-0x20], "hell"; mov word [rbp-0x1c], "o\0": a compiler's two stores.
void assembled_from_pieces() {
    const auto found = recover_stack_strings({write(-0x20, "hell", 1), write(-0x1c, std::string("o\0", 2), 2)});
    require(found.size() == 1, "pieces not joined into one string");
    require(found[0].offset == -0x20 && found[0].text == "hello" && found[0].byte_length == 5 &&
                found[0].encoding == Encoding::ascii && found[0].terminated,
            "wrong assembled string");
    require(found[0].orders == std::vector<std::uint64_t>{1, 2}, "orders do not cite both writes");
}

void later_writes_win_and_input_order_does_not_matter() {
    // "XXXXXXXX" is rewritten to "abcdXXXX" by a later store given first in the input.
    const auto found = recover_stack_strings({write(0, "abcd", 9), write(0, "XXXXXXXX", 3)});
    require(found.size() == 1 && found[0].text == "abcdXXXX" && !found[0].terminated &&
                found[0].orders == std::vector<std::uint64_t>{3, 9},
            "a later write did not replace earlier bytes");
    // Equal orders apply in input order: the second input write wins.
    const auto tie = recover_stack_strings({write(0, "aaaa", 5), write(0, "bbbb", 5)});
    require(tie.size() == 1 && tie[0].text == "bbbb", "equal orders not applied in input order");
}

void utf16_and_terminators() {
    const std::string wide("w\0i\0d\0e\0\0\0", 10);
    const auto found = recover_stack_strings({write(16, wide, 1)});
    require(found.size() == 1 && found[0].encoding == Encoding::utf16le && found[0].text == "wide" &&
                found[0].byte_length == 8 && found[0].terminated,
            "UTF-16 string not recovered");
    // A single NUL after UTF-16 is not a terminator.
    const auto open = recover_stack_strings({write(0, std::string("w\0i\0d\0e\0\0", 9), 1)});
    require(open.size() == 1 && !open[0].terminated, "half a UTF-16 terminator accepted");
    // A UTF-16 string can start at the last character of a short ASCII sequence.
    const auto mixed = recover_stack_strings({write(0, std::string("xyZ\0W\0V\0U\0", 11), 1)});
    require(mixed.size() == 1 && mixed[0].offset == 2 && mixed[0].text == "ZWVU" &&
                mixed[0].encoding == Encoding::utf16le,
            "UTF-16 inside a short ASCII prefix missed");
}

void gaps_split_runs_and_minimum_length() {
    // A one-byte gap at offset 4 separates "abcd" from "efgh".
    const auto found = recover_stack_strings({write(0, "abcd", 1), write(5, "efgh", 2)});
    require(found.size() == 2 && found[0].text == "abcd" && found[1].offset == 5 && found[1].text == "efgh",
            "a gap did not split runs");
    require(recover_stack_strings({write(0, std::string("abc\0", 4), 1)}).empty(), "short string reported");
    StackStringOptions one;
    one.minimum_length = 1;
    const auto shortest = recover_stack_strings({write(0, std::string("a\x01" "b", 3), 1)}, one);
    require(shortest.size() == 2 && shortest[0].text == "a" && shortest[1].text == "b",
            "minimum length 1 not honoured");
    // Tab, newline and CR are text; other control bytes end it.
    const auto escapes = recover_stack_strings({write(0, std::string("a\tb\nc\rd\x7f" "efgh", 12), 1)});
    require(escapes.size() == 2 && escapes[0].text == "a\tb\nc\rd" && escapes[1].text == "efgh",
            "control characters handled wrongly");
}

void negative_and_extreme_offsets() {
    const auto top = std::numeric_limits<std::int64_t>::max();
    const auto found = recover_stack_strings({write(top - 3, "tail", 1)});
    require(found.size() == 1 && found[0].offset == top - 3, "string ending at INT64_MAX lost");
    const auto bottom = std::numeric_limits<std::int64_t>::min();
    const auto low = recover_stack_strings({write(bottom, "head", 1)});
    require(low.size() == 1 && low[0].offset == bottom, "string at INT64_MIN lost");
    rejects([&] { (void)recover_stack_strings({write(top - 2, "tail", 1)}); }, "an overflowing range");
}

void limits() {
    rejects([] { (void)recover_stack_strings({write(0, "", 1)}); }, "an empty write");
    rejects([] { (void)recover_stack_strings({write(0, std::string(65, 'a'), 1)}); }, "a 65-byte write");
    StackStringOptions options;
    options.minimum_length = 0;
    rejects([&] { (void)recover_stack_strings({}, options); }, "minimum length 0");
    options.minimum_length = 65;
    rejects([&] { (void)recover_stack_strings({}, options); }, "minimum length 65");
    options.minimum_length = 4;
    options.maximum_writes = 1;
    rejects([&] { (void)recover_stack_strings({write(0, "a", 1), write(1, "b", 2)}, options); }, "too many writes");
    options.maximum_writes = 10;
    options.maximum_bytes = 7;
    rejects([&] { (void)recover_stack_strings({write(0, "abcdefgh", 1)}, options); }, "too many bytes");
    options.maximum_bytes = 8;
    require(recover_stack_strings({write(0, "abcdefgh", 1)}, options).size() == 1, "byte limit off by one");
    require(recover_stack_strings({}).empty(), "strings from no writes");
}

}  // namespace

int main() {
    try {
        assembled_from_pieces();
        later_writes_win_and_input_order_does_not_matter();
        utf16_and_terminators();
        gaps_split_runs_and_minimum_length();
        negative_and_extreme_offsets();
        limits();
    } catch (const std::exception& error) {
        std::cerr << "strings_test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "strings_test passed\n";
    return EXIT_SUCCESS;
}
