# Calling conventions during concurrent reads

Two readers opening a saved Program can disagree about a function's calling
convention. On the GCC x86-64 `types` fixture, the ELF entry point at
`ram:00101080` has Ghidra's `processEntry` convention. A concurrent read
returned `unknown`. The decompiler then assigned different argument types and
storage to the function and emitted different C for its startup call.

The affected file is
`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/data/CallingConventionDBAdapterV0.java`.
Its blob in `Ghidra_12.2_build` is `0464b75f682d6753f55d4bc7c2eaea8551d4fcc4`.
[Upstream source](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/data/CallingConventionDBAdapterV0.java)

`DataTypeManagerDB.getCallingConventionName` takes a shared read lock. The
upstream adapter assigns its lookup maps before reading their rows from the
database. A second reader can see the maps during that interval, miss a valid
ID, and return before the first reader has finished. Both reads can take place
at the same Program modification number. Replaying dependencies and checking
that modification number cannot distinguish this case.

In the source-built application the adapter builds both maps and the free-ID
set in local variables under a shared initializer monitor. It publishes them
after the table scan succeeds. A failed scan can be retried. The change also
protects the first readers after Ghidra invalidates the cache.

For the extension on official 12.2, BinaryRat loads the convention names under
the Program database's exclusive lock before it admits decompiler work. It
releases the lock before starting or waiting on native workers. This is a
read-only operation and creates no undo entry. Callers opening a session while
holding only a database read lock must release it first. The bridge check
protects initialization at session startup. The fork's adapter change also
covers other tools that read the table directly.

## Verification and upstream updates

The original hosted failure replayed 20 candidate cache entries on reopen. Its
ordered reference returned different C and a different prototype for one
function. A local reproduction on the same ELF produced the same incorrect
export digest. A controlled two-reader test reproduced the missing convention
by pausing the initial database scan before it had read the stored rows.
[Original hosted run](https://github.com/YurilLAB/BinaryRat/actions/runs/46135376240)

The direct adapter test failed in all 20 trials against official 12.2 and
passed in all 20 against the corrected adapter. It checks a stored name on
first load, then writes a second name, invalidates the reader and checks both
lookup directions. [Concurrency test](../../../Ghidra/Framework/SoftwareModeling/src/test/java/ghidra/program/database/data/CallingConventionDBAdapterV0Test.java)

At each upstream merge, inspect how the adapter initializes, invalidates and
publishes its ID-to-name and name-to-ID maps. Remove this patch when the new
upstream passes the cold concurrent-reader test unaided. Repeat the single-slot
and parallel comparisons after reopen and edit, and remeasure the LLVM export.
[Export benchmark](../evidence/llvm19-linux.md)
