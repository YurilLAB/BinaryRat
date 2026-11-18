/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 YurilLAB
 */

typedef unsigned int Word;

typedef struct LayoutFixture {
    Word tag;
    Word reserved[3];
    Word payload;
    Word alternate;
} LayoutFixture;

#define EXPORTED __attribute__((noinline, visibility("default")))

EXPORTED Word layout_leaf(const volatile LayoutFixture *value) {
    return value->payload;
}

EXPORTED Word layout_alternate(const volatile LayoutFixture *value) {
    return value->alternate;
}

EXPORTED Word layout_middle(const volatile LayoutFixture *value) {
    return layout_leaf(value) + 1;
}

EXPORTED Word layout_top(const volatile LayoutFixture *value) {
    return layout_middle(value) + 2;
}

EXPORTED Word layout_start(const volatile LayoutFixture *value) {
    return layout_top(value) + 3;
}

EXPORTED Word layout_deeper(const volatile LayoutFixture *value) {
    return layout_start(value) + 9;
}

EXPORTED Word layout_right(const volatile LayoutFixture *value) {
    return layout_leaf(value) + 4;
}

EXPORTED Word layout_diamond(const volatile LayoutFixture *value) {
    Word left = layout_middle(value);
    return left + layout_right(value);
}

EXPORTED Word layout_shift_middle(const volatile LayoutFixture *value) {
    return layout_leaf(value + 1) + 5;
}

EXPORTED Word layout_shift(const volatile LayoutFixture *value) {
    Word shifted = layout_shift_middle(value);
    return shifted + layout_middle(value);
}

EXPORTED Word layout_cycle_b(const volatile LayoutFixture *value);

static volatile Word layout_cycle_gate;

EXPORTED Word layout_cycle_a(const volatile LayoutFixture *value) {
    Word nested = layout_cycle_b(value);
    return value->tag + nested;
}

EXPORTED Word layout_cycle_b(const volatile LayoutFixture *value) {
    if (layout_cycle_gate) {
        return layout_cycle_a(value) + 7;
    }
    return value->payload;
}

EXPORTED Word layout_cycle_entry(const volatile LayoutFixture *value) {
    return layout_cycle_a(value) + 8;
}

#define LEAF(ID) \
    static __attribute__((noinline)) Word leaf##ID(const volatile LayoutFixture *value) { \
        return value->payload + (ID); \
    }

LEAF(1)
LEAF(2)
LEAF(3)
LEAF(4)
LEAF(5)
LEAF(6)
LEAF(7)
LEAF(8)
LEAF(9)
LEAF(10)
LEAF(11)
LEAF(12)

#define BRANCH(ID, FIRST, SECOND, THIRD) \
    static __attribute__((noinline)) Word branch##ID(const volatile LayoutFixture *value) { \
        Word left = leaf##FIRST(value); \
        Word middle = leaf##SECOND(value); \
        return left + middle + leaf##THIRD(value); \
    }

BRANCH(1, 1, 2, 3)
BRANCH(2, 4, 5, 6)
BRANCH(3, 7, 8, 9)
BRANCH(4, 10, 11, 12)

EXPORTED Word layout_broad(const volatile LayoutFixture *value) {
    Word first = branch1(value);
    Word second = branch2(value);
    Word third = branch3(value);
    return first + second + third + branch4(value);
}

EXPORTED Word layout_fanout(const volatile LayoutFixture *value) {
    Word first = leaf1(value);
    Word second = leaf2(value);
    Word third = leaf3(value);
    Word fourth = leaf4(value);
    return first + second + third + fourth + leaf5(value);
}

int fixture_entry(void) {
    return 0;
}
