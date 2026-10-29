# ADR-0041: Telemetry lake: Parquet on object storage, queried in process

- **Status**: proposed
- **Date**: 2026-10-29

Issue #77. This is the first checkbox of #77 ("ADR for format + query engine"): it proposes the
format, the query engine, the layout and the retention mechanism, and says which decisions are the
owner's. Nothing is built by this ADR.
The number is the next free one on `main` at the time of writing (0039 and 0040 are proposed in
open PRs), so renumber on merge if another lands first.

## Context

`POST /api/ingest/events` counts each event into fleet prevalence and keeps nothing: **an accepted
event is gone**, and the agent has already deleted its copy
(`docs/architecture/control-plane.md`, "Server behavior today (interim)"). Consumers that wait for
the lake: hunting over archived events (#933), `graph` and `prevalence` rebuilds (#72, #76),
retrospective detection and ML corpora (`server/datalake/README.md`).

What is fixed already (`server/datalake/README.md`, #77): object storage is the ground truth,
partitioned tenant / day / event type, columnar; a hot recent window serves interactive queries;
retention is per tenant and deletion is provable. Postgres stays the system of record for
detections, cases and policy.

What the deployment is today: `server/docker-compose.yml` runs Postgres 15, the Next.js server and
nginx. There is no object store, no worker process and no cluster.

What an event is: the canonical `schema::Event` JSON (a `type` and a `meta` carrying
`timestamp_ns`), batches of up to 100 per request, at most 1000 and 4 MiB. The schema is versioned
and gains variants; old fixtures must stay readable.

## Decision

### 1. The format is Parquet, with a few typed columns and the event as a JSON column

One row per event. Typed columns for what every query filters or joins on: `tenant_id`,
`agent_id`, `event_type`, `ts` (from `meta.timestamp_ns`, clamped as ingest already does),
`schema_version`, and the few fields prevalence already extracts (image hash, image path, parent
and child image, DNS domain). The whole event stays in one `event` JSON column, byte for byte as
received. A new event variant or field therefore needs no migration of files already written, and
the typed columns can be extended by a later file version. A query that needs a field that is not
typed reads it from the JSON column (slower, correct).

### 2. The layout is Hive-style, so that a partition is a prefix

`tenant=<id>/date=<YYYY-MM-DD>/type=<event_type>/<file>.parquet`. Tenant first: one tenant's data
is one prefix, which is what makes per-tenant retention and deletion a prefix operation and what
makes a tenant-scoped query unable to read another tenant's files. `date` is the event's day (UTC),
not the arrival day, so a flushed spool lands where the event happened.

### 3. The write path is micro-batch files, then compaction

Ingest does not write to the object store on the request path. It appends the accepted batch to a
local durable queue (a Postgres table) in the same transaction as the prevalence counters, and a
writer drains it into one small Parquet file per (tenant, day, type) per flush. A compaction job
merges the small files of a closed day into few large ones. The agent's `2xx` means "durably
queued", not "in the lake": the lag is a number the health console shows (it already counts ingest
lag).

The hot window is the uncompacted files of the last day or two. Interactive latency there is paid
in file count, which compaction bounds; this is the part to measure before trusting (see
"Measurements owed").

### 4. The query engine is DuckDB, in process, on a worker

DuckDB reads Parquet from the object store with partition pruning on `tenant`, `date` and `type`,
and runs inside a worker, not inside the Next.js request. The hunt layer compiles a validated query
to SQL as it already does for the Postgres source (ADR-0025), with the same bounds: statement
timeout, searches in flight per tenant, a row never carrying more than the page needs. The tenant
predicate is a path prefix first and a column filter second.

### 5. Retention is a prefix deletion with an audit record

A per-tenant policy gives the retention in days. The retention job deletes the `date=` prefixes
older than that and writes an audit row: tenant, prefix, object count, bytes, the manifest hash of
the listing it deleted, when, and by which job run. "Provable" means that record plus a listing
that shows the prefix empty after the deletion; it does not mean the bytes are unrecoverable from
the storage provider's own backups or versioning, which the deployment must turn off or age out
for the lake bucket.

### 6. Out of scope here

`cloud-detection` streaming, the ML dataset provenance pointers, and any change to the agent. The
agent keeps its contract (`2xx` drops the segment).

## Alternatives considered

- **ClickHouse (or another columnar server).** The best interactive latency and a real hot tier.
  It adds a stateful cluster to a deployment that has none, and the retention proof becomes a table
  operation, not a prefix listing. Kept as the exit if the in-process engine does not hold (see
  below): the Parquet files are readable by it, so choosing Parquet now does not close that door.
- **Postgres partitioned tables (or Timescale).** One system and no new service. It keeps the raw
  events beside the case store, which the issue says not to do, and it is the wrong cost per byte
  for the volume this is meant to hold.
- **Delta Lake or Iceberg over Parquet.** Gives atomic commits and schema evolution. It also adds a
  catalog and a writer protocol that this volume does not yet need; a day prefix with compaction
  covers the same ground here. Revisit with the volume.

## Consequences

- #933 can be built: the events source is a third `HuntQuery` source reading through the engine.
- Ingest gains a queue table and a writer; a failed object-store write does not fail the request,
  it delays the lake and shows as lag.
- The deployment gains an object store. For a self-hosted install that is a MinIO (or any
  S3-compatible service); this is a decision of the owner's (below).
- Provable deletion is real for the lake bucket and stated as such, not for the provider's backups.
- Everything in "Measurements owed" is unmeasured; the engine and the hot-window design are
  assumptions until it is.

## Decisions only the owner can make

- [ ] **Engine:** DuckDB in process (proposed), or ClickHouse.
- [ ] **Object store** for a self-hosted install (MinIO proposed) and which cloud object store for a
  hosted one.
- [ ] **Retention defaults** per tenant, and whether a tenant may set zero (keep nothing).
- [ ] **Crypto-shredding** (a per-tenant data key whose destruction makes the files unreadable) in
  addition to prefix deletion. It strengthens "provable" against provider backups and costs key
  management; not proposed for the first slice.
- [ ] **ADR-0025 point 9** (ad-hoc search), which #933 also waits on through #910.

## Measurements (2026-10-29, one lab run) and what is still owed

One agent (`agent capture-events`, Fedora 43 lab VM, kernel 7.2.9) for 601 s under a synthetic loop
(execs, file writes, DNS, connects every 0.2 s; capture in `lab/captures/test-77-20261029/`), then
the events written as Parquet (zstd) in this ADR's layout with DuckDB 2.0.0 on the host, local disk.

| What | Result |
|---|---|
| Events, raw JSON-Lines | 480 484 events, 134.9 MB, about 800 events/s, about 280 B per event |
| Share of volume | `file_open` 431 800 events (90 %, 120 MB), then `file_write` 24 732, `exec` 12 368, `socket_create` 4 560, `connect` 3 130, `identity_change` 2 256 |
| Parquet, one file per (tenant, day, type) | 9.1 MB in 11 files: about 15x smaller than the JSON |
| Parquet, one file per type per 10 s flush | 10.9 MB in 539 files |
| Queries, compacted | count by type 2.8 ms; `exec` with `comm='bash'` (1 020 rows) 2.2 ms; one type partition with a `daddr` filter 2.4 ms; scan of a field inside the JSON column (`fd`) 113 ms |
| Queries, 539 small files | 42.7 ms, 28.1 ms, 7.7 ms, 98.2 ms |

What this supports: Parquet with typed columns plus the event as JSON is small and fast enough for a
hunt-style query on one agent's 10 minutes; typed columns and partition pruning are what keep it
fast, and a field read from the JSON column costs a full scan; many small files cost about an order
of magnitude on the typed queries even on a local disk.

What it does **not** support, and is still owed:
- **Per agent per day.** The loop is synthetic and a `file_open` flood drives the volume. A day on a
  real host, and the fleet's shape, are not measured; do not size storage from 800 events/s.
- **Object store.** Everything ran on a local disk. Over S3 each file is a round trip, so the
  539-file case is the optimistic one; compaction cadence cannot be chosen from these numbers.
- **N days over several tenants**, the "Done when" of #77.
- **Writer lag** after an outage flush.
- `file_open` being 90 % of the bytes is a decision to take (sample, filter at the agent, or
  keep): not made here.
