# Native protocol v1 (experimental)

Launch `binaryrat-engine serve --cache DIRECTORY`. One process exclusively owns
each directory; a second owner fails, and OS locks release on process exit.
Do not share it with direct library instances. The protocol runs over UTF-8
stdin/stdout; diagnostics go to stderr. Requests are serialized in this MVP.
Input lines are limited to 16 MiB. End-of-input shuts down cleanly.

```json
{"id":"1","op":"ping","protocol_version":1}
```

Success: `{"id":"1","ok":true,"protocol_version":1,"result":{...}}`.
Error: `{"id":"1","ok":false,"protocol_version":1,"error":{"code":"...","message":"..."}}`.
Malformed requests do not terminate the server. A malformed request without a
usable ID returns a null ID. IDs and operations must be strings.

Operations:

| Operation | Fields | Result |
|---|---|---|
| `ping` | none | Engine/version/capabilities |
| `cache.put` | `key`, `value`, `dependencies` | `stored` |
| `cache.get` | `key` | `hit`, `value` |
| `cache.invalidate` | `dependencies` | `removed` |
| `types.recover` | `observations`, optional `maximum_extent` | `layouts`, `rejected`, `score_kind` |

Cache keys require `schema_version:1`, `ghidra_version:"12.2"`, `program_id`,
`revision` (nonnegative integer), `address_space`, `address`, `body_sha256`, and
`options_digest`. Additional fields are preserved in the canonical SHA-256 key.
Callers must add all semantic state dependencies. These required fields are a
minimum shape, not a proof of complete cache identity. In particular, the bridge's
`revision` is process-local. Do not reuse across unrelated imports merely because
that number matches. Dependency identities are nonempty strings. Invalidations
currently scan stored entries; there is no automatic Ghidra event subscription
or disk-quota eviction yet. Cache reads reject corrupt/checksum-mismatched data.

An observation has `object_id`, signed-64-bit `offset`, unsigned-64-bit `width`,
optional unsigned `stride`, `evidence_id`, and boolean `object_start_known`.
Unknown origins abstain. Overlap is exposed as ambiguity; it does not prove a
union. Minimum extent is a lower bound, not an exact allocation size or array
length. `evidence_strength` is explicitly uncalibrated, not a probability.
