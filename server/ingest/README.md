# server/ingest

Agent-facing ingestion service: terminates agent mTLS connections, validates and stores
uploaded events and detections, and tracks agent heartbeats (silence is a detection).

Routes (`server/app/api/`): `ingest/events` (batches of `schema::Event` from the agent
spool), `ingest/heartbeat`, `ingest/detection`; the agent's `/api/v1/ingest/*` paths
are re-exports. Contract: `docs/architecture/control-plane.md`. Events are counted
into fleet prevalence and not retained until the telemetry lake exists.
