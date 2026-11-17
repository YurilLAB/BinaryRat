/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 YurilLAB. New BinaryRat ground-truth fixture.
 */
#include <stdint.h>
#include <stdio.h>

#if defined(_MSC_VER)
#define BR_NOINLINE __declspec(noinline)
#else
#define BR_NOINLINE __attribute__((noinline))
#endif

typedef union Payload {
    uint64_t word;
    double real;
    uint8_t bytes[8];
} Payload;

typedef struct Record {
    int32_t id;
    uint16_t flags;
    uint8_t tag;
    uint8_t reserved;
    struct Record *next;
    Payload payload;
    int32_t samples[4];
} Record;

#pragma pack(push, 1)
typedef struct PackedRecord {
    uint8_t tag;
    uint32_t sequence;
} PackedRecord;
#pragma pack(pop)

typedef int32_t (*RecordOperation)(Record *, int32_t);

BR_NOINLINE int32_t update_record(Record *record, int32_t increment) {
    record->id += increment;
    record->samples[record->tag & 3] += increment;
    return record->id;
}

BR_NOINLINE int64_t sum_records(const Record *record) {
    int64_t result = 0;
    while (record != NULL) {
        unsigned i;
        result += record->id + record->flags;
        for (i = 0; i < 4; ++i) {
            result += record->samples[i];
        }
        record = record->next;
    }
    return result;
}

BR_NOINLINE double read_real(const Payload *payload) {
    return payload->real;
}

BR_NOINLINE uint32_t read_packed(const PackedRecord *record) {
    return record->sequence + record->tag;
}

int main(void) {
    Record tail = { 2, 3, 1, 0, NULL, { 11 }, { 1, 2, 3, 4 } };
    Record head = { 7, 5, 2, 0, &tail, { 13 }, { 5, 6, 7, 8 } };
    PackedRecord packed = { 4, 17 };
    Payload real;
    RecordOperation operation = update_record;
    real.real = 1.5;
    operation(&head, 2);
    printf("%lld %u %.1f\n", (long long) sum_records(&head),
           (unsigned) read_packed(&packed), read_real(&real));
    return 0;
}
