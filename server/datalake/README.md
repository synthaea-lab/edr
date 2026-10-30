# server/datalake — Telemetry Lake

The full-fidelity telemetry substrate: every event agents upload (the canonical
schema serialization) lands here, beyond what Postgres keeps. Postgres remains the
system of record for detections/cases/policy; the lake is the system of record for
**raw telemetry at scale** — cheap, columnar, time-partitioned, retention-managed.

Consumers (the lake exists because all of these need the same substrate):
- `server/cloud-detection` — streaming + batch + retrospective detection
- `server/hunt` — ad-hoc queries over full history, not just the case store
- `server/graph` + `server/prevalence` — projections/counters rebuild from it
- `ml/` — training corpora and per-site adaptation datasets (`datasets/` provenance
  points at lake partitions, closing the reproducibility loop)

Shape (tech locked by ADR at implementation, not here): object storage as the
ground truth (partitioned by tenant/day/event-type, columnar format), a query engine
over it, and a hot recent window for interactive latency. Retention is per-tenant
policy; deletion is provable (compliance is a feature).

Design: [ADR-0041](../../docs/adr/0041-telemetry-lake-format-and-query-engine.md) (Parquet on object
storage, queried in process; status **proposed**, decisions taken under the owner's delegation).

## What is built (issue #77, first slice: the write path)

- **Queue.** `POST /api/ingest/events` inserts each accepted batch into `lake_batches` when `LAKE_DIR`
  is set (`lib/lake-writer.ts`, `enqueueLakeBatch`). `LAKE_DIR` unset means off: nothing is queued.
- **Writer.** `GET /api/cron/write-lake` (`CRON_SECRET` bearer) drains up to `LAKE_WRITER_MAX_BATCHES`
  batches (default 200) into
  `tenant=<id>/date=<YYYY-MM-DD>/type=<event_type>/<flush>.parquet`, one file per (tenant, day, type)
  per call, then deletes the queue rows, in one transaction. It answers `503` while the lake is off and
  returns `remaining`, so a schedule that does not keep up shows as a number that grows. Schedule it
  like the other crons.
- **File.** Columns `agent_id`, `ts`, `comm`, `path`, `image_path`, `daddr`, `query`, `sha256`, and
  `event` (the event's source text as the agent sent it: the queue holds the text of each element of
  the body's `events`, so integers above 2^53 such as `meta.timestamp_ns` are not rounded; a queue row
  written before this holds a parsed object and is serialised, with the rounding). Tenant, date and type are in the path, not
  in the file. An event type that is not `[a-z][a-z0-9_]{0,63}` goes under `type=other`; its real type
  stays in `event`. Compression is Snappy (`hyparquet-writer`, pure JavaScript).
- **Store.** A directory (`LAKE_DIR`, `FsLakeStore`: a mounted volume) or an S3-compatible bucket
  (`LAKE_S3_BUCKET`, `S3LakeStore`), both with `put`, `list` and `delete`. The directory store writes
  to a temporary name and renames, and `delete` removes the directories it empties; an S3 PUT is
  atomic. Setting both is refused. The lake is on when either is set.

  | Variable | Meaning |
  |---|---|
  | `LAKE_S3_BUCKET` | The bucket. Required to use S3. |
  | `LAKE_S3_ENDPOINT` | A custom endpoint (MinIO-like servers); unset for AWS S3. |
  | `LAKE_S3_REGION` | Default `us-east-1`. |
  | `LAKE_S3_ACCESS_KEY_ID`, `LAKE_S3_SECRET_ACCESS_KEY` | Set both or neither; neither uses the SDK's default credential chain (instance role, environment). |
  | `LAKE_S3_PREFIX` | A key prefix inside the bucket, to share it. |
  | `LAKE_S3_FORCE_PATH_STYLE` | `true` or `false`; defaults to `true` when an endpoint is set. |

  **The bucket must not be versioned**: on a versioned bucket a delete leaves a delete marker and the
  bytes, so a `lake_deletions` row would say "verified empty" about a prefix whose objects still exist.
  The retention job checks it: once per run, before it lists or deletes anything, it asks the bucket for
  its versioning status (`GetBucketVersioning`) and answers `500` with the reason when the status is
  `Enabled` or `Suspended` (earlier versions are kept) or cannot be read. The credentials of the writer
  and retention job therefore need `s3:GetBucketVersioning`, besides put, list and delete. Writer and
  retention need bucket-wide write and delete: the query side (DuckDB, not built) must use separate
  read-only credentials, ideally scoped to one tenant prefix, never these (ADR-0041, decision 4).
- **Retention setting.** `tenants.lake_retention_days` (default 90). `0` makes the writer drop that
  tenant's events (counted as `droppedNoRetention`). An event dated at or past its tenant's retention
  (ingest keeps past timestamps) is dropped and counted as `droppedPastRetention`, so a prefix the
  retention job deleted never refills.
- **Retention job.** `GET /api/cron/prune-lake` (`CRON_SECRET` bearer; run it once a day) deletes every
  `date=` partition whose age in UTC days has reached its tenant's retention (`0` keeps nothing, today
  included), one partition at a time, and keeps a `lake_deletions` row for each:
  - **Written before the deletion**, from the listing: tenant, date, file count, bytes, a SHA-256 over
    the sorted `key:size` lines, run id, start time. If that row cannot be written the partition is not
    deleted and waits for the next run.
  - **Completed after it**, from what the prefix lists afterwards, not from what the store claimed: how
    many files really went (`deleted_count`), how many are still there (`failed_count`), the first error,
    whether every file of the starting listing is gone (`verified_empty`), and `completed_at`. A file the
    writer put under the prefix meanwhile is not in that listing: it is counted in `arrived_during_deletion`,
    is not a failure, and is deleted by the next run. `bytesDeleted` adds the sizes of the files that went.
  - A row with `completed_at` null is a deletion that started and was never recorded as finished (a crash,
    or the database going away): the files may or may not be gone.
  - A failure on one partition is recorded and the run goes on to the next, so one bad tenant does not
    stop the others. The route answers `500` with the counts and the first errors when any partition was
    not fully deleted or could not be recorded.
  - A partition that keeps failing adds one row per daily run: that is the signal.
  - The row has no foreign key to the tenant, so it outlives it.
  A `tenant=` prefix whose tenant is not in Postgres is **not** deleted: it is counted as
  `orphanTenantPrefixes` and left for a person. Keys that are not a `tenant=…/date=YYYY-MM-DD/…`
  partition are never touched. "Provable" means the audit row; it does not reach a storage provider's
  backups or versioning (ADR-0041). `LakeStore.delete` reports `{ deleted, failed }` per key instead of
  throwing, because by the time a later key fails the earlier ones are already gone.

## The query side (issue #77, `lib/lake-query.ts`)

`queryLake(reader, { tenantId, from, to, types?, where?, limit? })` reads events back: a tenant, a
range of UTC days (both included, at most 366), optionally event types and exact matches on `agentId`,
`comm`, `path`, `imagePath`, `daddr`, `query`, `sha256` (compared in lowercase), and a row limit
(default 100, at most 1000). It lists the partitions in range **one day at a time** (and one type at a
time when `types` is given, at most 32), so a tenant's history outside the range is never listed, and it
asks the reader for at most the files still wanted plus one (`list(prefix, { limit })`): the writer makes a
file per flush, so a tenant's prefix has no ceiling, and listing it whole to cut it afterwards would cost
unbounded time and memory (a review point on #1084). At most 2000 files are listed and read; the partition
path does the pruning (the files of a type that was not asked for are not read). It reads them with
`hyparquet` and filters the rows. Rows come back oldest first, each with `event`, the event's source text
as ingest received it. The result says when it was cut: `truncated` (more rows than `limit`) and
`listingTruncated` (more than 2000 matching files exist: the answer is incomplete; `filesSkipped` is then 1,
"at least one", not a count).

- **Tenant isolation is structural, in two layers.** Every listing is under the tenant's own prefix, for
  an id from a closed character set; and every key the store lists is parsed against the whole layout and
  ignored unless its tenant, day and type are the ones asked for, so a store that answers a wider prefix
  reads nothing of another tenant's. There is no query language for a compiler bug to widen.
- **Not DuckDB, for now.** ADR-0041 decision 4 plans DuckDB, but its Node bindings have no Alpine build
  (ADR, "Findings") and the image is Alpine. `hyparquet` is pure JavaScript, already a dependency, and
  runs in the image. The cost is a scan of every file in range: fine for a hunt over days on one tenant,
  not measured at fleet volume, and the result shape is what a hunt layer consumes, so the engine can
  change under it. The ADR's other isolation requirement (read-only credentials) is a store matter:
  `LakeReader` (`list`, `get`) is separate from `LakeStore` so the reader can be built on its own
  credentials. Only the directory store implements it; the S3 reader waits for the S3 store (#1052).
- **Two options for a caller** (#933): `order: "desc"` (the newest rows, newest first; the default is
  the oldest first), `includeEvent: false` (the `event` column is not read from the file) and `signal`
  (an `AbortSignal` checked before each file, so a caller can bound the time).
- **The hunt `events` source** (#933, `server/hunt/README.md`, ADR-0025 point 10) is the one caller:
  `POST /api/hunts/search` with `source: "events"`.
- **Not built:** time-of-day bounds finer than a day, filters other than equality, ordering other than
  by time, compaction-aware reading, a cursor over the archive.

## What is not built

- An object store in `server/docker-compose.yml`: the compose still has only Postgres, the server and
  nginx, so `LAKE_S3_*` points at a store you run yourself. See the ADR on which one.
- Compaction: every drain writes new small files.
- Saved hunts over events (the ad-hoc search is #933), and DuckDB for fleet volume.
- A bound on the queue: if `LAKE_DIR` is set and the cron is not scheduled, `lake_batches` grows
  without limit.
- Duplicates: a crash between the file writes and the commit can leave the events of that flush
  twice (see `lib/lake-writer.ts`). Nothing removes a duplicate.
- Exactness of large integers: ingest parses the body with `JSON.parse`, so a value above 2^53 (a
  nanosecond timestamp, a process generation) is stored as the nearest double.
