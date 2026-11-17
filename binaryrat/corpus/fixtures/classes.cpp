/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 YurilLAB. New BinaryRat ground-truth fixture.
 */
#include <cstdint>
#include <iostream>

#if defined(_MSC_VER)
#define BR_NOINLINE __declspec(noinline)
#else
#define BR_NOINLINE __attribute__((noinline))
#endif

struct Left {
    virtual ~Left() = default;
    virtual std::int64_t left() const = 0;
};

struct Right {
    virtual ~Right() = default;
    virtual std::int64_t right() const = 0;
};

class Item : public Left, public Right {
public:
    explicit Item(std::int64_t value) : value_(value) {}
    std::int64_t left() const override { return value_; }
    std::int64_t right() const override { return value_ + 3; }
protected:
    std::int64_t value_;
};

class Derived final : public Item {
public:
    explicit Derived(std::int64_t value) : Item(value) {}
    std::int64_t left() const override { return value_ * 2; }
};

struct Root {
    virtual ~Root() = default;
    std::int32_t root = 5;
};
struct First : virtual Root { std::int32_t first = 7; };
struct Second : virtual Root { std::int32_t second = 11; };
struct Diamond final : First, Second { std::int32_t leaf = 13; };

BR_NOINLINE std::int64_t evaluate(const Left *left) {
    const Right *right = dynamic_cast<const Right *>(left);
    return left->left() + (right != nullptr ? right->right() : 0);
}

BR_NOINLINE std::int32_t evaluate_diamond(const Diamond *value) {
    return value->root + value->first + value->second + value->leaf;
}

int main() {
    Derived value(19);
    Diamond diamond;
    std::cout << evaluate(&value) << ' ' << evaluate_diamond(&diamond) << '\n';
}
