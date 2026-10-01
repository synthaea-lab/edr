# server/ingest

Agent-facing ingestion service: terminates agent mTLS connections, validates and stores
uploaded events and detections, and tracks agent heartbeats (silence is a detection).

Routes (`server/app/api/`): `ingest/events` (batches of `schema::Event` from the agent
spool), `ingest/heartbeat`, `ingest/detection`; events and heartbeat also have
`/api/v1/ingest/` aliases. Contract: `docs/architecture/control-plane.md`. Events are counted
into fleet prevalence and not retained until the telemetry lake exists.

`POST /api/ingest/detection` accepts the JSON shape of `schema::Detection`
(`timestamp_ns`, `severity`, `title`, `source`, optional `score` and
`attributions`, `techniques`, `events`). It keeps the previous single-event
payload for older agents. The first event is stored in `Detection.event`; the
remaining events and the structured fields are retained in `Detection.meta`.
The correlator's `source.case_id` is retained there as an agent-local identity.
The current producer derives it from `ppid:comm`, which can recur after process
or agent restarts. `Detection.caseId` is a foreign key to a server `Case` UUID;
direct grouping needs a stable, collision-resistant source key and a
tenant-and-agent-scoped mapping to that UUID.
