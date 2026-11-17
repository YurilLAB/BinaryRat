# Default-branch-only upstream synchronization

The sole branch is `master`, initially anchored at `Ghidra_12.2_build`.
Initial fork creation copied upstream master; before any BinaryRat commits the
fresh fork pointer was initialized to the verified release using an exact
force-with-lease expectation. This initialization is not a routine sync method.

All new commits, including merges/reverts, use author `yurillab` and its approved
GitHub-linked email. Preserve all upstream authors and history. Do not add
co-author or AI-attribution trailers. No topic, pull-request, or sync branches.
Detached validation checkouts and recovery tags are allowed.

For a future official release, with a clean working tree and serialized writer:

```sh
git switch master
git tag binaryrat-before-RELEASE HEAD
git fetch --no-tags upstream refs/tags/Ghidra_RELEASE_build:refs/tags/upstream/Ghidra_RELEASE_build
git merge --no-ff --no-commit refs/tags/upstream/Ghidra_RELEASE_build
```

Verify the official release commit and available provenance first. Resolve
conflicts directly, review every core-patch ledger entry, refresh toolchain pins
and version adapters, and update `UPSTREAM.json`. Commit as `yurillab`, validate
that exact commit using detached checkouts, then push `master`. Run every required
CI lane for every new first-parent SHA. Do not use jobs that silently discard
older pending commits. `git merge --abort` abandons an uncommitted failed sync;
after publication, use a reviewed revert rather than rewriting shared history.

Direct default-branch commits make post-push CI evidence essential; releases
must reference a fully verified SHA. A new release is not certified until source
builds, exact parity, mutation/protection/reversal checks, accuracy evaluation,
and maintained benchmarks pass on its supported platforms.
