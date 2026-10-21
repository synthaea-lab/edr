# Common-set snapshot: wire format v1

The artifact ADR-0020 decision 1 ships to the agent: the image hashes seen on at least K
hosts of one tenant, as a Bloom filter. This page is the byte layout and the sizing rules;
the plan that puts it to use is `fleet-prevalence-snapshot-plan.md` (slices 1 and 2).

The layout is shared by a TypeScript writer (`server/lib/common-set-snapshot.ts`) and a Rust
reader (`crates/ml`). `ml/tests/fixtures/common_set_snapshot_golden.json`, generated from a
third, stdlib-only implementation (`gen_common_set_snapshot_golden.py`), fixes the exact bytes
and both sides test against it. Changing anything below is a `format_version` bump, not an
edit.

## Layout

All integers are little-endian. The header is 32 bytes, then the filter body.

| Offset | Size | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 4 | magic | ASCII `SYCS` |
| 4 | 2 | `format_version` | `1` |
| 6 | 2 | `hash_count` | bit positions per hash, 1 to 16 |
| 8 | 4 | `min_hosts` | K: hosts a hash was seen on to be a member |
| 12 | 4 | `hosts_covered` | distinct agents that had reported when the snapshot was built |
| 16 | 4 | `entry_count` | distinct hashes inserted |
| 20 | 4 | `bit_count` | filter size in bits: a multiple of 8, at least 64 |
| 24 | 8 | `built_at` | Unix seconds when the snapshot was built |
| 32 | `bit_count / 8` | body | the filter |

A reader rejects a snapshot whose magic or version it does not know, whose `hash_count` or
`bit_count` is out of range, or whose length is not exactly `32 + bit_count / 8`. It never
guesses.

## Membership

The input is a normalized SHA-256: 64 lowercase hex characters (the server's counter key, and
`normalize_sha256` on both sides of the rarity seam). The digest is already uniform, so the
filter uses it directly:

```
h1 = first 8 bytes of the digest as a little-endian u64
h2 = next 8 bytes as a little-endian u64, OR 1 (odd)
position_i = ((h1 + i * h2) mod 2^64) mod bit_count      for i in 0 .. hash_count
```

Bit `p` is bit `p mod 8` (least significant first) of body byte `p / 8`. A hash is a member
when all of its bits are set. As with any Bloom filter, a non-member may read as a member; a
member never reads as a non-member.

## Sizing (writer)

For `n` distinct hashes and a target false-positive rate `p`:

```
n = 0:   bit_count = 64, hash_count = 1
n > 0:   bits = ceil(n * ln(1/p) / ln(2)^2), rounded up to a multiple of 8, at least 64
         hash_count = clamp(floor(bits / n * ln(2) + 0.5), 1, 16)
```

Hashes are inserted in sorted order after deduplication, so the same set always gives the same
bytes. The writer takes a byte cap and refuses to build past it (an explicit error, never a
silent truncation: a filter missing members would read as "rare" for common binaries); the
caller raises K or lowers the target rate. The reader does not need the target rate, it is
recorded in the manifest entry's metadata (ADR-0020).

## Where the agent reads it

`<content_root>/snapshots/common-set.bin` (the content directory `agent run` loads rules from;
`<state_dir>/content` by default), loaded at start and on every `ReloadContent`:

- **Absent** is "no snapshot yet": none is held and the "not in the common set" evidence is
  withheld. A snapshot removed by a later content release unloads the held one.
- **Present but unusable** (unreadable, over 64 MiB, or refused by the reader's strict checks)
  keeps the snapshot already in force and logs the reason (never the bytes), the posture the
  rule and YARA directories already have: a bad file must not leave a live agent without it.
- The file is read whole, capped at 64 MiB (the manifest allows 100 MiB per artifact; the
  server caps the snapshot it builds well below that), and swapped as one value.

The path is fixed on the agent: every tenant's manifest can use the same `path` for its own
snapshot entry, because the server's artifact store is keyed by content hash, not path, and
shared across tenants (#804) — two tenants' snapshots land under their own hash automatically,
since their bytes differ, with no tenant-unique naming needed on either side (slice 5 of
`fleet-prevalence-snapshot-plan.md`).

## Delivery: the signed manifest (ADR-0033)

The artifact above reaches an agent through a manifest of its own, not the content manifest and
not the rings. One manifest per tenant, replaced by each build:

```json
{
  "built_at": 1760000000,
  "entry_count": 4096,
  "hosts_covered": 12,
  "kind": "common-set",
  "min_hosts": 3,
  "schema_version": 1,
  "sha256": "<the artifact's SHA-256, lowercase hex>",
  "signature": "<Ed25519, lowercase hex>",
  "size": 5432
}
```

The signature is over the canonical bytes of the same document with `signature` set to `""`:
2-space-indented JSON, keys sorted at every level (the content manifest's scheme).
`tests/fixtures/snapshot-manifest-golden.json` holds one signed by the public test key; the
TypeScript signer (`server/lib/snapshot-manifest.ts`) and the Rust verifier (`crates/updater`)
both test against it. `built_at` equals the artifact header's `built_at`.

- **Endpoints**, agent mTLS, tenant from the certificate: `GET /api/snapshot/manifest` (404 when
  nothing is published) and `GET /api/snapshot/artifact[?sha256=]` (409 when the hash is not the
  stored one).
- **Builder:** `GET /api/cron/build-snapshots` (CRON_SECRET), meant to run daily. Guards before a
  signature is requested: the tenant has at least `SNAPSHOT_MIN_HOSTS_COVERED` reporting hosts;
  `built_at` is later than the snapshot in force; the entry count is not below
  `SNAPSHOT_MIN_ENTRY_FRACTION` of the previous one unless the hosts covered fell too; the set is
  never truncated (`SNAPSHOT_MAX_ENTRIES`) or over `SNAPSHOT_MAX_BYTES`. A refusal keeps the
  previous snapshot served. `SNAPSHOT_MIN_HOSTS` is K. The defaults are provisional until slice 6.
- **Signing:** the `snapshot` key signs this kind only. Its custody is not decided (#753), so
  the only signer is the **public test key**, enabled by `SYNTHAEA_SNAPSHOT_SIGNER=test`; without
  it the cron answers 503 and nothing is published. Never set it on a production deployment.
- **The agent** (`agent/src/snapshot_fetch.rs`, `updater::snapshot`): a loop inside `agent run`
  polls the manifest about every six hours (jittered; `SYNTHAEA_SNAPSHOT_POLL_SECS` overrides it
  for a lab run, floor 5 s), and does nothing unless the build embeds a `snapshot` key
  (`updater::key::SNAPSHOT_PUBLIC_KEY`: none in a build without the `test-key` feature, so the
  loop is off in production until #753 provisions one). It verifies the signature against that key
  alone, refuses a `built_at` not later than the snapshot in force or more than 15 minutes ahead of
  its clock, an offer already past the maximum age (provisionally 3 days), a declared size over the
  64 MiB cap, an artifact whose size or SHA-256 differs from the signed ones or whose header
  disagrees with the manifest, and anything that does not parse. Only then does it write
  `snapshots/common-set.bin` atomically and reload that one file. A refusal keeps the snapshot in
  force and is logged with its reason. A snapshot older than the maximum age is also treated as
  absent where the evidence is judged, so the evidence is withheld when the server stops
  publishing.
- **Not done here:** tenant binding (a `tenant_id` in the manifest and the tenant identifier at
  enrollment, ADR-0033 decision 3, required before production), and reporting a refused snapshot
  on the health beacon (it is logged only: a beacon field is a schema change).

