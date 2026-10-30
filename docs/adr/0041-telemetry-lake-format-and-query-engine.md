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
received: that includes integers above 2^53 (`meta.timestamp_ns` is about 1.8e18), so the path from
the request body to the file must carry the event's source text, never a `JSON.parse` followed by a
`JSON.stringify`, which rounds them. A new event variant or field therefore needs no migration of files already written, and
the typed columns can be extended by a later file version. A query that needs a field that is not
typed reads it from the JSON column (slower, correct).

### 2. The layout is Hive-style, so that a partition is a prefix

`tenant=<id>/date=<YYYY-MM-DD>/type=<event_type>/<file>.parquet`. Tenant first: one tenant's data
is one prefix, which is what makes per-tenant retention and deletion a prefix operation and what
makes a tenant-scoped query unable to read another tenant's files. `date` is the event's day (UTC),
not the arrival day, so a flushed spool lands where the event happened.

Two rules keep the layout honest. The `type=` segment is agent-supplied text (ingest only checks that
it is a string), so it is validated against a closed character set before it shapes a path, and an
event that fails is not written under it. And a past timestamp is not trusted: ingest clamps only the
future (24 h), so a spool flushed after an outage, or a buggy or compromised agent, can name a day
that is already past retention, possibly one the retention job deleted and recorded as empty. The
writer therefore drops, and counts, the events older than the tenant's retention at write time (the
next retention run would delete them anyway), so a prefix recorded as deleted never refills.

### 3. The write path is micro-batch files, then compaction

Ingest does not write to the object store on the request path. It appends the accepted batch to a
local durable queue (a Postgres table), by its own insert (prevalence counters are best effort and
are not in the same transaction), and a writer drains it into one small Parquet file per (tenant, day, type) per flush. A compaction job
merges the small files of a closed day into few large ones. A "closed" day is not final: an event
with a past timestamp that is still inside retention can add a file to it days later, so compaction
must be able to re-compact a day, and must not assume that a day it compacted stays alone. The agent's `2xx` means "durably
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

**Tenant isolation has two independent layers, as a requirement of the engine slice and not a detail
of the hunt compiler.** The worker's DuckDB must not hold the writer's bucket-wide credentials: a
compiler bug, or a query feature added later, would then be a cross-tenant read. The query side gets
read-only credentials, and each query is confined to the tenant's prefix by a mechanism that does
not depend on the SQL it runs: either DuckDB restricted per query to `tenant=<id>/` (`allowed_directories`
with external access off, then `lock_configuration`), or per-tenant S3 credentials scoped by a bucket
policy to that prefix (MinIO supports prefix conditions). The prefix in the SQL is the second layer.

### 5. Retention is a prefix deletion with an audit record

A per-tenant policy gives the retention in days. The retention job deletes the `date=` prefixes
older than that and writes an audit row: tenant, prefix, object count, bytes, the manifest hash of
the listing it deleted, when, and by which job run. "Provable" means that record plus a listing
that shows the prefix empty after the deletion; it does not mean the bytes are unrecoverable from
the storage provider's own backups or versioning, which the deployment must turn off or age out
for the lake bucket. The retention job checks this instead of trusting the deployment: before it
deletes anything it asks the store for the bucket's versioning status and refuses to run when it is
`Enabled` or `Suspended` (a suspended bucket still keeps earlier versions), because a delete on a
versioned bucket leaves a marker and the bytes, and the audit row would then claim an empty prefix
that is not.

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
- **The ingest queue is unbounded, and it lives in Postgres.** Decision 3 queues each accepted batch
  in a Postgres table until the writer drains it. If the writer is not scheduled, or the object
  store is down, nothing drains it and the table grows without limit in the system of record that
  this ADR says stays separate from the lake: a lake outage becomes a database-disk problem for the
  detections and cases too. **Unresolved.** The options each cost something: refuse ingest (`503`)
  past a bound, which makes a lake outage an ingest outage and the agents spool; drop the oldest
  queued batches, which loses telemetry silently unless it is counted and alerted; or leave it
  unbounded and alert on queue depth, which delays the problem. The first slice (`lib/lake-writer.ts`)
  does none of them: it returns `remaining` from the writer's cron so a growing queue is visible, and
  queues nothing while `LAKE_DIR` is unset. A bound, and what happens at it, is a decision for the
  slice that adds compaction, and needs a measured queue depth under an outage to size.
- Everything in "Measurements owed" is unmeasured; the engine and the hot-window design are
  assumptions until it is.

## Decisions taken under the owner's delegation, 2026-10-29

The owner said "prends les décisions sur l'ADR pour 77". Taken by session edr-repo-49. The status of
this ADR stays **proposed**: acceptance is the owner's, on the PR. Each decision below is reversible
before code exists; the ones that stop being reversible once data is written say so.

- **Engine: DuckDB in process, on a worker.** Parquet is the contract, not DuckDB: the files stay
  readable by ClickHouse, so choosing the engine now does not lock the data. The exit is the one in
  "Alternatives considered", taken if the measurements owed below show the in-process engine does
  not hold over an object store.
- **Object store: the S3 API is the interface, MinIO is what the self-hosted compose runs.** The
  server talks to "an S3-compatible endpoint, bucket and credentials" from its configuration, and
  nothing else. **Not decided here:** which hosted provider or account, because that is a fact about
  accounts and vendors (as the custody of #753), not a design choice.
- **Retention default: 90 days per tenant, set per tenant, from 0 to 365 days.** `0` means the writer
  skips that tenant (nothing is kept). Provisional: a number chosen without a compliance requirement
  or a measured volume, to be revisited with both. Lowering a tenant's retention deletes at the next
  job run; raising it never brings back what was deleted.
- **Crypto-shredding: not in the first slice.** Prefix deletion with an audit row is what is built.
  Revisit when a customer or a regulation asks to survive provider backups, since it adds key
  management for every tenant.
- **ADR-0025 point 9: already confirmed on 2026-10-21** under the same delegation (comment on #910),
  so it no longer blocks #933. Not a decision of this ADR.
- **What the lake stores: everything the agent uploads, `file_open` included, for the first slice.**
  The lake is the ground truth, and sampling at the agent or filtering in the writer would make the
  archive unable to answer questions nobody has asked yet. This is the decision that stops being
  reversible as data is written (what was never stored cannot be recovered). It is revisited after
  one measurement on a real host over a day, since `file_open` was 90 % of the bytes in the lab run
  below, and the writer may then drop or sample it behind a per-type setting.

## Findings from building the write path (2026-10-29)

Building the first slice (`server/lib/lake-writer.ts`, PR stacked on this one) showed three things
this ADR did not say.

- **DuckDB's Node bindings have no Alpine (musl) build.** `@duckdb/node-bindings` ships linux-x64
  and linux-arm64 for glibc, plus macOS and Windows; the server image is `node:20-alpine`
  (`server/Dockerfile`). Decision 4 ("DuckDB in process, on a worker") therefore cannot run in the
  current image. The write path does not need it (Parquet is written by `hyparquet-writer`, pure
  JavaScript, which runs on Alpine). The query side must pick one of: a glibc base image for the
  worker, a separate worker container, or the DuckDB CLI as a subprocess. Not decided here; it is the
  first thing the query slice (#933) has to settle, and the engine stays an assumption until then.
- **The writer's compression is Snappy, not zstd.** The lab measurement used zstd through DuckDB
  (about 15x smaller than the JSON); `hyparquet-writer` writes Snappy by default and zstd needs an
  external compressor. Files will be larger than the measured ones; the size is not measured for the
  writer's output.
- **The event column is not byte for byte.** Ingest reads the body with `JSON.parse`, so an integer
  above 2^53 (a nanosecond timestamp, a process generation) is stored as the nearest double. The file
  holds what ingest parsed, serialized again. Exactness would need ingest to keep the raw text.

- **MinIO's container images could not be pulled on 2026-10-29.** `docker.io/minio/minio` and
  `quay.io/minio/minio` both refused the pull from this machine, and `bitnami/minio` has no manifest.
  The decision "MinIO runs in the self-hosted compose" therefore has no image to point at here; I did
  not establish why (a registry change, or this machine). The S3 store (`lib/lake-s3-store.ts`) speaks
  the S3 API only and was run against SeaweedFS 4.50 (`chrislusf/seaweedfs`, pulled and working),
  which is what the integration tests used. Which store the compose ships is open again: the decision
  stays "the S3 API is the interface", and the choice of server (SeaweedFS, Garage, RustFS, a hosted
  one) is not made. RustFS (`rustfs/rustfs`) pulled but exited at start with the arguments I gave it,
  and was not investigated; Garage pulled and was not run.

The slice also fixes two choices this ADR left open: the queue is a table with one row per batch and
the events as a JSON column, and the stores are a directory (`LAKE_DIR`) and an S3 bucket (`LAKE_S3_BUCKET`)
behind the same interface (`put`, `list`, `delete`).

## Findings from building the query side (2026-10-30)

The first read slice (`server/lib/lake-query.ts`) settles the question the findings above left open:
which engine runs in the image. Decision taken under the owner's delegation ("oui" to building the
query layer): **the first slice reads with `hyparquet`, not DuckDB.** It is pure JavaScript, already a
dependency, and runs on Alpine; DuckDB would have needed a glibc worker image or a subprocess, a
deployment change that is not worth making before the volume is measured. A query is structured
(tenant, days, types, equality filters, limit) and scans every file in range; it is bounded (366 days,
2000 files, 1000 rows) and says when it was cut. Reversible: the result shape is the contract, and
DuckDB, on a glibc worker, remains the plan if a measured hunt over a fleet's volume is too slow.

Isolation (decision 4's two layers) is met here by construction instead of by DuckDB settings: every
listing is under the tenant's prefix, one day (and type) at a time and never past the file cap, and every
listed key is re-checked against the tenant, the day and the type asked for. The read-only
credentials requirement stays open for the S3 reader: `LakeReader` is its own interface so those
credentials need not be the writer's. Not measured: query time on any volume.

## Decisions on the prevalence rebuild, 2026-10-30

Taken under the owner's delegation ("prends les décisions que tu recommandes") by session edr-repo-81, from the
six questions the rebuild slice (#1086) left in `issues/issue-77.md`. Reversible before an apply path exists.

1. **The counters table stays authoritative; the lake rebuild is a check.** The lake is bounded by its
   retention (90 days by default) and the table keeps 180, so the lake cannot be the source. A difference
   between a rebuild and the table is a signal to look at, not a normal state.
2. **No backfill is written for now.** A replace would destroy counters older than the lake's retention and a
   merge would double count. An apply path waits for a stated need and its own decision.
3. **A tenant whose lake window cannot cover the range is reported, not refused.** Retention 0 keeps no events,
   and the writer drops events past retention: for such a tenant the rebuild answers `complete: false`.
4. **The detection route keeps counting its observations.** `POST /api/ingest/detection` counts events that are
   not in the lake, so counters can exceed a rebuild by those; this is documented. Changing what the counters
   count is a prevalence decision, not a lake one.
5. **Duplicates are removed in the writer, not in the rebuild.** The archive is fixed at its source, which also
   serves the hunt (#933). Tracked in #1093.
6. **The graph stays computed on read.** A materialised projection rebuilt from the lake would be a new store
   with its own retention; reopen it only if a consumer needs the graph as of a past date.

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
