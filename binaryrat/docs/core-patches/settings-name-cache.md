# Decompiler reads of data settings

During a warm export of a GCC x86-64 ELF, the stock decompiler requested a
global's mutability setting while BinaryRat replayed another function's
queries. Ghidra raised a `NullPointerException` inside
`SettingsDBAdapterV1.getNameIndex`. The ordered reference completed 19 of the
20 functions. An independent serial export completed all 20.

The affected file is
`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/data/SettingsDBAdapterV1.java`.
Its blob at `Ghidra_12.2_build` is `a6573c90457fcf3eb1e2ffa107e33013cde73d09`.
[Upstream source](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/data/SettingsDBAdapterV1.java)

Ghidra uses two lookup maps to translate between database IDs and setting
names. On a cold read, one thread could observe the first map while the second
was still null. The source-built fork makes readers wait until initialization
is complete. The change affects in-memory lookups and requires no migration
of stored settings.

The BinaryRat extension also supports an unmodified Ghidra 12.2 installation.
It primes the default-settings and instance-settings name tables under the
Program database lock before launching workers. Ghidra exposes no public
operation that initializes both tables for an arbitrary Program. The bridge
therefore depends on private 12.2 adapter members at startup. Revalidate their
names and semantics when updating the supported Ghidra version.

The regression pauses the initial scan, issues a second real lookup and
checks the stored setting. All 30 trials against official 12.2 missed a
stored record. All 30 trials with the patched adapter passed, including
invalidation, lookup of the newly stored name and lookup of missing settings.
[Concurrency test](../../../Ghidra/Framework/SoftwareModeling/src/test/java/ghidra/program/database/data/SettingsDBAdapterV1Test.java)

At upstream sync, check that both maps become available together on first
access and after cache invalidation. Run the concurrent-reader regression
and compare all records against a fresh serial decompile of the same Program
before removing this patch. [Related calling-convention regression](calling-convention-cache.md)
