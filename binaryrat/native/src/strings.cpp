// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <binaryrat/strings.hpp>

#include <algorithm>
#include <limits>
#include <map>
#include <numeric>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>

namespace binaryrat::strings {
namespace {

struct Cell {
    std::uint8_t value = 0;
    std::uint64_t order = 0;
};

bool printable(std::uint8_t value) noexcept {
    return (value >= 0x20 && value <= 0x7e) || value == '\t' || value == '\n' || value == '\r';
}

void validate(const std::vector<StackWrite>& writes, const StackStringOptions& options) {
    if (options.minimum_length < 1 || options.minimum_length > maximum_minimum_length)
        throw std::invalid_argument("minimum_length must be 1 to 64");
    if (writes.size() > options.maximum_writes)
        throw std::invalid_argument("too many stack writes");
    for (const auto& write : writes) {
        if (write.bytes.empty() || write.bytes.size() > maximum_write_bytes)
            throw std::invalid_argument("a stack write must hold 1 to 64 bytes");
        // The last byte's offset must fit: offset + size - 1 <= INT64_MAX.
        const auto last = static_cast<std::int64_t>(write.bytes.size() - 1);
        if (write.offset > std::numeric_limits<std::int64_t>::max() - last)
            throw std::invalid_argument("stack write range overflows");
    }
}

// Collects the orders of cells [begin, end) into a sorted, duplicate-free list.
std::vector<std::uint64_t> orders_of(const std::vector<Cell>& run, std::size_t begin, std::size_t end) {
    std::set<std::uint64_t> orders;
    for (std::size_t index = begin; index < end; ++index) orders.insert(run[index].order);
    return {orders.begin(), orders.end()};
}

void scan_run(std::int64_t start, const std::vector<Cell>& run, std::size_t minimum,
              std::vector<StackString>& found) {
    std::size_t index = 0;
    while (index < run.size()) {
        std::size_t wide = 0;
        while (index + 2 * wide + 1 < run.size() && printable(run[index + 2 * wide].value) &&
               run[index + 2 * wide + 1].value == 0)
            ++wide;
        if (wide >= minimum) {
            const std::size_t end = index + 2 * wide;
            const bool terminated = end + 1 < run.size() && run[end].value == 0 && run[end + 1].value == 0;
            StackString text;
            text.offset = start + static_cast<std::int64_t>(index);
            text.byte_length = 2 * wide;
            text.encoding = Encoding::utf16le;
            for (std::size_t unit = 0; unit < wide; ++unit)
                text.text.push_back(static_cast<char>(run[index + 2 * unit].value));
            text.terminated = terminated;
            const std::size_t consumed = end + (terminated ? 2 : 0);
            text.orders = orders_of(run, index, consumed);
            found.push_back(std::move(text));
            index = consumed;
            continue;
        }
        std::size_t narrow = 0;
        while (index + narrow < run.size() && printable(run[index + narrow].value)) ++narrow;
        if (narrow >= minimum) {
            const std::size_t end = index + narrow;
            const bool terminated = end < run.size() && run[end].value == 0;
            StackString text;
            text.offset = start + static_cast<std::int64_t>(index);
            text.byte_length = narrow;
            text.encoding = Encoding::ascii;
            for (std::size_t unit = 0; unit < narrow; ++unit)
                text.text.push_back(static_cast<char>(run[index + unit].value));
            text.terminated = terminated;
            const std::size_t consumed = end + (terminated ? 1 : 0);
            text.orders = orders_of(run, index, consumed);
            found.push_back(std::move(text));
            index = consumed;
            continue;
        }
        // A UTF-16 string can begin at the last character of a short ASCII sequence.
        ++index;
    }
}

}  // namespace

const char* encoding_name(Encoding encoding) noexcept {
    return encoding == Encoding::utf16le ? "utf16le" : "ascii";
}

std::vector<StackString> recover_stack_strings(const std::vector<StackWrite>& writes,
                                               const StackStringOptions& options) {
    validate(writes, options);
    std::vector<std::size_t> sequence(writes.size());
    std::iota(sequence.begin(), sequence.end(), std::size_t{0});
    std::stable_sort(sequence.begin(), sequence.end(), [&](std::size_t left, std::size_t right) {
        return writes[left].order < writes[right].order;
    });
    std::map<std::int64_t, Cell> memory;
    for (const auto position : sequence) {
        const auto& write = writes[position];
        for (std::size_t byte = 0; byte < write.bytes.size(); ++byte) {
            memory[write.offset + static_cast<std::int64_t>(byte)] = Cell{write.bytes[byte], write.order};
            if (memory.size() > options.maximum_bytes)
                throw std::invalid_argument("stack writes cover too many bytes");
        }
    }
    std::vector<StackString> found;
    std::vector<Cell> run;
    std::int64_t start = 0;
    std::int64_t next = 0;
    for (const auto& [offset, cell] : memory) {
        if (run.empty() || offset != next) {
            scan_run(start, run, options.minimum_length, found);
            run.clear();
            start = offset;
        }
        run.push_back(cell);
        // The map is ordered, so offset + 1 only overflows at INT64_MAX, the last key.
        next = offset == std::numeric_limits<std::int64_t>::max() ? offset : offset + 1;
    }
    scan_run(start, run, options.minimum_length, found);
    return found;
}

}  // namespace binaryrat::strings
