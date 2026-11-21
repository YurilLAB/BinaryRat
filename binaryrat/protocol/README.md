# Native protocol v1 (experimental)

Launch `binaryrat-engine serve --cache DIRECTORY`. One process exclusively owns
each directory; a second owner fails, and OS locks release on process exit.
Do not share it with direct library instances. The protocol runs over UTF-8
stdin/stdout; diagnostics go to stderr. Input lines are limited to 16 MiB and
to 64 levels of nested arrays and objects. Lines are bytes ended by one LF on
every platform; a CR before it is ignored in requests and never written.
End-of-input shuts down cleanly: queued leases are cancelled, running leases
receive `lease.stop` with reason `shutdown`, and an attached process still
running when `kill_grace_ms` expires is killed before the engine exits.

```json
{"id":"1","op":"ping","protocol_version":1}
```

Success: `{"id":"1","ok":true,"protocol_version":1,"result":{...}}`.
Error: `{"id":"1","ok":false,"protocol_version":1,"error":{"code":"...","message":"..."}}`.
A cache record the engine may not write or remove fails that request with
`operation_failed` and a message naming the operation (`write cache record`,
`replace cache record`, `remove cache record`) and the system's reason, never a
path. At start-up a record that can be neither read nor deleted is skipped: it is
never served, and a later write replaces it.
Malformed requests do not terminate the server. A malformed request without a
usable ID returns a null ID: a line that is not UTF-8 JSON, is too long or
nests too deeply is refused as `invalid_request` before its ID is read. Bytes
that are not UTF-8 appear as U+FFFD in error messages. IDs and operations must
be strings.

Requests are read in order and every operation except `sched.acquire` answers
before the next request is read. `sched.acquire` answers when its lease is
granted, so its response may arrive after later responses: match responses by
`id`. Lines with an `event` field instead of an `id` are scheduler events:
`{"event":"lease.stop","lease":"...","reason":"timeout|cancelled|memory|shutdown"}`
tells the holder to stop its work and release, and
`{"event":"lease.killed","lease":"...","pid":N}` reports that the engine killed
the attached process of a holder that did not release in time.

Operations:

| Operation | Fields | Result |
|---|---|---|
| `ping` | none | Engine/version/capabilities |
| `cache.put` | `key`, `value`, `dependencies`, optional `as_of` | `stored` |
| `cache.get` | `key` | `hit`, `verified`, `value`, `seq`, `generation` |
| `cache.changed` | `dependencies`, or `all: true` | `removed`, `seq` |
| `cache.invalidate` | `dependencies` | `removed`, `seq` (same as `cache.changed`) |
| `cache.confirm` | `key`, `seq`, `generation` | `confirmed` |
| `cache.evict` | `key` | `removed` |
| `cache.stats` | none | entry, dependency, journal and hit counters |
| `sched.configure` | optional `cpu_workers`, `worker_cap`, `ram_bytes`, `jvm_reserve_bytes`, `other_reserve_bytes`, `worker_bytes`, `max_pending`, `memory_poll_ms`, `kill_grace_ms` | `workers`, measured `machine`, `pool_bytes`, `memory_watch` |
| `sched.acquire` | `lease`, optional `reserve_bytes`, `timeout_ms` | when granted: `granted: true`, `waited_ms`; never granted: `granted: false`, `status` |
| `sched.attach` | `lease`, `pid` | `attached`, `resident_bytes` |
| `sched.release` | `lease` | `status`, `run_ms`, `peak_resident_bytes`, `killed` |
| `sched.cancel` | `lease` | `cancelled` |
| `sched.stats` | none | workers, queued, running, peaks, per-status counts |
| `types.recover` | `observations` (see below), optional `maximum_extent` | `layouts` (fields and `union_candidates`), `rejected`, `score_kind` |
| `types.solve` | `summaries`, `edges`, `roots` (1 to 16), optional `maximum_extent`, `maximum_states`, `maximum_derived` (each at most 65536) | `components`, `roots` (`states`, `derived`, `layout`, `rejected`, completeness), `score_kind` |
| `strings.stack` | `groups` (`id`, `writes`), optional `minimum_length` (1 to 64, default 4) | `groups` (`id`, `strings`), `minimum_length` |

## Scheduler

`sched.configure` runs once per session. CPU count and physical memory default
to what the engine measures (process affinity, and Linux cgroup CPU and memory
limits, applied). Workers are
`min(cpu_workers, worker_cap, (ram_bytes - jvm_reserve_bytes - other_reserve_bytes) / worker_bytes)`.
A lease is granted when a worker is free and its reservation (at least
`worker_bytes`) fits the remaining pool, strictly first in, first out. A
reservation larger than the pool is rejected at once; a full queue
(`max_pending`) is refused instead of blocking the reader.

The lease deadline counts from the grant. A deadline, `sched.cancel`, or an
attached process whose resident memory (Windows working set, Linux RSS, polled
every `memory_poll_ms`) exceeds the lease's reservation produces `lease.stop`.
Attachment requires a readable resident-memory sample. A failed replacement
leaves the existing attachment in place. The holder keeps the worker and
reservation until `sched.release`. When a positive `kill_grace_ms` expires,
the engine can terminate the attached process using a Windows
process handle or a Linux pidfd and a matching start time. On Linux hosts where
pidfds are unavailable, the holder must stop the process and release the lease.
`sched.release` reports `completed`, `timed_out`, `cancelled`,
`memory_exceeded` or `failed`. Lease names are client-chosen, 1 to 256
characters, unique among live leases.

## Cache keys

Schema 1 keys require `schema_version:1`, `ghidra_version:"12.2"`, `program_id`,
`revision` (nonnegative integer), `address_space`, `address`, `body_sha256`, and
`options_digest`; the caller vouches that the key names a complete program state.
The bridge's `revision` is process-local; do not reuse across unrelated imports
merely because that number matches. Function bytes and the in-memory modification
number alone cannot establish correctness across reopen or import, and plain
exports are evidence artifacts, not reusable decompilations.

Schema 2 keys are live: `schema_version:2`, `ghidra_version`, `kind`,
`program_id`, `address_space`, `address`, `options_digest`, and no `revision`.
Their validity comes from dependency tracking instead. Additional fields are
preserved in the canonical SHA-256 key. Dependency identities are nonempty
strings. Cache reads reject corrupt/checksum-mismatched data.

## Live cache

Every entry lists the program facts it was computed from. `cache.changed`
reports one program change: entries depending on any listed dependency are
removed at once (through an in-memory dependency index, not a scan), and
`all: true` reports a change of unknown reach, which leaves every entry
unverified instead. Changes are numbered (`seq`). `cache.get` returns
`verified: false` for an entry that a change of unknown reach may have
affected, and for every entry written by an earlier session (changes made while
no session watched were never reported); the caller must check such an entry
against the program and then `cache.confirm` it with the `seq` and `generation`
from that `cache.get`, or `cache.evict` it. A value computed while changes were
arriving is put with `as_of`, the `seq` read before computing it; it is stored
unverified if a later journaled change could have affected it, or if the
journal no longer reaches back to `as_of`. There is no disk-quota eviction yet.

## Layout recovery

A `types.recover` observation has `object_id`, signed-64-bit `offset`,
unsigned-64-bit `width`, optional unsigned `stride`, `evidence_id`, boolean
`object_start_known`, and optional `storage_view`: `integer` or
`floating_point` (any other value is an `invalid_request`). Unknown origins
abstain. Overlap is exposed as ambiguity; it does not prove a union. Minimum
extent is a lower bound, not an exact allocation size or array length.

Each layout lists `fields` and `union_candidates`. A union candidate is one
offset read through both an integer view (width 1, 2, 4 or 8) and a
floating-point view (width 4 or 8) by distinct evidence; each entry has
`offset`, `views` (`kind`, `width`, `evidence_ids`) and `evidence_strength`.
Strided observations and evidence labelled with both views do not count.
`evidence_strength` is explicitly uncalibrated, not a probability.

## Summary propagation

`types.solve` propagates per-parameter access summaries over calls. A summary
is an `id` and `accesses` (signed `offset`, `width`, `evidence_id`, optional
`storage_view`); offsets may be negative because a callee can receive an
interior pointer. An edge (`caller`, `callee`, signed `offset`, `evidence_id`)
states that the callee's pointer equals the caller's plus `offset`. Each root
names a summary and the `object_id` whose start its parameter is asserted to be.

Strongly connected summaries form a `component`. It is `consistent` when every
cycle sums to offset zero and the members' positions fit a signed 64-bit value;
then all paths between two members agree. Otherwise its internal edges are
listed in `withheld_edges` and never followed. Each root searches
(summary, offset) states breadth-first. `states` record `summary`, `offset`,
`hops`, and the `edge` and `parent` of one shortest path. `derived` rows give
each reached access at its object offset (`state`, `access` index, `offset`,
`width`, `evidence_id`, `storage_view`) and are aggregated as in
`types.recover` into `layout` (null when nothing is accepted) and `rejected`
(by `derived_index`). A root is `complete` unless it reached a withheld edge
(`withheld_components`) or an offset sum overflowed (`overflowed`). More than
`maximum_states` (default 4096) or `maximum_derived` (default 16384) gives
status `state_limit` or `derived_limit` and no partial output. Results do not
depend on input order; duplicate edges collapse onto the lowest index.

## Stack strings

`strings.stack` assembles text from constant stores to a stack frame. Each group
(a unique nonempty `id`) holds `writes`: a signed stack `offset`, `bytes` (1 to
64 bytes of lowercase hex in memory order) and an unsigned `order`. Writes apply
in ascending `order`, ties in input order, so each stack byte keeps its last
value. The written bytes split into contiguous runs, and each run is scanned
from its lowest offset: a UTF-16LE string of at least `minimum_length`
printable ASCII code units is taken first, otherwise an ASCII string of at
least `minimum_length` bytes. Printable means 0x20 to 0x7e, tab, newline or
carriage return. A string also consumes the NUL terminator that follows it
(two zero bytes for UTF-16) and is then `terminated`. Each string reports
`offset`, `byte_length` (text only), `encoding` (`ascii` or `utf16le`), `text`
and the `orders` of the writes behind its text and terminator, ascending. A
group holds at most 65536 writes over at most 1 MiB of distinct bytes, a request
at most 65536 groups and 1048576 writes, and a range that passes the largest
signed 64-bit offset is refused.
