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
- **Store.** A directory (`FsLakeStore`): a mounted volume. Writes go to a temporary name and are
  renamed.
- **Retention setting.** `tenants.lake_retention_days` (default 90). `0` makes the writer drop that
  tenant's events (counted as `droppedNoRetention`). **Nothing deletes old files yet.**

## What is not built

- The S3 store (the ADR makes the S3 API the interface; MinIO in the compose). Only the directory
  store exists.
- Compaction: every drain writes new small files.
- The retention job (prefix deletion with an audit row) and any use of `lake_retention_days` beyond `0`.
- The query side (#933): DuckDB reading these files, and a `HuntQuery` events source.
- A bound on the queue: if `LAKE_DIR` is set and the cron is not scheduled, `lake_batches` grows
  without limit.
- Duplicates: a crash between the file writes and the commit can leave the events of that flush
  twice (see `lib/lake-writer.ts`). Nothing removes a duplicate.
- Exactness of large integers: ingest parses the body with `JSON.parse`, so a value above 2^53 (a
  nanosecond timestamp, a process generation) is stored as the nearest double.
