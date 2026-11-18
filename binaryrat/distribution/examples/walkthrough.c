// Copyright 2026 YurilLAB
// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
#include <stdio.h>

struct Measurement {
    int count;
    int width;
    int height;
};

#ifdef _WIN32
#define RETAIN_FUNCTION __declspec(dllexport) __declspec(noinline)
#else
#define RETAIN_FUNCTION __attribute__((visibility("default"), noinline))
#endif

RETAIN_FUNCTION int measurement_area(const struct Measurement *measurement)
{
    return measurement->count * measurement->width * measurement->height;
}

int main(void)
{
    const struct Measurement readings[] = {{2, 10, 4}, {1, 5, 3}, {3, 7, 2}};
    int total = 0;
    for (size_t i = 0; i < sizeof(readings) / sizeof(readings[0]); ++i) {
        total += measurement_area(&readings[i]);
    }
    printf("Total measured area: %d\n", total);
    return 0;
}
