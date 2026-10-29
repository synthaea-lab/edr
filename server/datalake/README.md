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

Proposed design: [ADR-0041](../../docs/adr/0041-telemetry-lake-format-and-query-engine.md) (Parquet
on object storage, queried in process; status **proposed**, the engine and the object store wait on
the owner). Nothing is built yet.
