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
  `event` (the event as JSON, after ingest's `JSON.parse`). Tenant, date and type are in the path, not
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

  **The bucket must not be versioned** (or its old versions must be aged out): on a versioned bucket a
  delete leaves a delete marker and the bytes, so a `lake_deletions` row would say "verified empty"
  about a prefix whose objects still exist. The store does not check this.
- **Retention setting.** `tenants.lake_retention_days` (default 90). `0` makes the writer drop that
  tenant's events (counted as `droppedNoRetention`).
- **Retention job.** `GET /api/cron/prune-lake` (`CRON_SECRET` bearer; run it once a day) deletes every
  `date=` partition whose age in UTC days has reached its tenant's retention (`0` keeps nothing, today
  included) and writes one `lake_deletions` row per partition: tenant, date, file count, bytes, a
  SHA-256 over the sorted `key:size` listing that was deleted, whether the prefix listed empty
  afterwards, the run id and the time. The row has no foreign key to the tenant, so it outlives it. A
  partition that still lists files after the deletion is recorded as not verified empty and the route
  answers `500` with the counts. A `tenant=` prefix whose tenant is not in Postgres is **not** deleted:
  it is counted as `orphanTenantPrefixes` and left for a person. Keys that are not a
  `tenant=…/date=YYYY-MM-DD/…` partition are never touched. "Provable" means the audit row; it does
  not reach a storage provider's backups or versioning (ADR-0041).

## What is not built

- An object store in `server/docker-compose.yml`: the compose still has only Postgres, the server and
  nginx, so `LAKE_S3_*` points at a store you run yourself. See the ADR on which one.
- Compaction: every drain writes new small files.
- Skipping at write time an event already older than its tenant's retention: the writer files it, and
  the next `prune-lake` deletes it and records the deletion.
- The query side (#933): DuckDB reading these files, and a `HuntQuery` events source.
- A bound on the queue: if `LAKE_DIR` is set and the cron is not scheduled, `lake_batches` grows
  without limit.
- Duplicates: a crash between the file writes and the commit can leave the events of that flush
  twice (see `lib/lake-writer.ts`). Nothing removes a duplicate.
- Exactness of large integers: ingest parses the body with `JSON.parse`, so a value above 2^53 (a
  nanosecond timestamp, a process generation) is stored as the nearest double.
