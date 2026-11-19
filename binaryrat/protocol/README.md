# Native protocol v1 (experimental)

Launch `binaryrat-engine serve --cache DIRECTORY`. One process exclusively owns
each directory; a second owner fails, and OS locks release on process exit.
Do not share it with direct library instances. The protocol runs over UTF-8
stdin/stdout; diagnostics go to stderr. Input lines are limited to 16 MiB.
End-of-input shuts down cleanly: queued leases are cancelled, running leases
receive `lease.stop` with reason `shutdown`, and an attached process still
running when `kill_grace_ms` expires is killed before the engine exits.

```json
{"id":"1","op":"ping","protocol_version":1}
```

Success: `{"id":"1","ok":true,"protocol_version":1,"result":{...}}`.
Error: `{"id":"1","ok":false,"protocol_version":1,"error":{"code":"...","message":"..."}}`.
Malformed requests do not terminate the server. A malformed request without a
usable ID returns a null ID. IDs and operations must be strings.

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
merely because that number matches.

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
