# Control Plane

Server-side design: enrollment/PKI, ingest, detection store, policy and content
distribution, case queries, console. Technology choices recorded here once made.

## Agent heartbeat contract

Every agent that uploads (every `agent run` that is not `--standalone`) tells the control plane it is alive by
sending its health beacon. Heartbeats keep `agent.lastSeen` fresh even when
there are no events to upload.
Event ingestion also updates `lastSeen`; the silent-agent check watches that
field.

### Request

`POST <server>/api/ingest/heartbeat`, with a JSON body
(`transport::DEFAULT_HEARTBEAT_ENDPOINT`, sent by `TransportClient::send_heartbeat`;
served by `server/app/api/ingest/heartbeat/route.ts`). The `/api/ingest/`
prefix is covered by nginx's mTLS `location` and allowed through the server
middleware without a console session. The `/api/v1/ingest/` alias is covered
too (see the event ingest contract below); unrelated paths may be redirected
to `/login`. `transport`'s `the_heartbeat_endpoint_is_a_real_server_route`
test fails if the constant stops matching a route.

| Aspect | Contract |
| --- | --- |
| Sent by | the health collector (`agent/src/health.rs`), wired by `commands::common::health_collector`: Linux and Windows. macOS doesn't beacon yet, because it has no silence monitor to feed the collector. |
| Cadence | every 30 s (`health::DEFAULT_INTERVAL`). The first beacon goes out 30 s after start. |
| Delivery | best-effort. A failed `POST` is logged at `debug` and never retried or spooled: the next tick is the retry. Beacons don't go through the event spool, so a backlog of events never delays one. |
| Identity | the mTLS client certificate. nginx terminates TLS and forwards `X-Client-Cert-Verified` and `X-Client-Cert-Subject`, and the server takes the enrollment ID from the subject's `CN`. `agent_id` in the body is `null` today and is never trusted. |

Body (`HeartbeatPayload` wrapping `schema::HealthBeacon`):

```json
{
  "agent_id": null,
  "beacon": {
    "timestamp_ns": 1790756620574604200,
    "agent_version": "0.1.0",
    "sensors": [
      { "name": "windows-etw", "pulse_count": 42, "silent": false }
    ],
    "spool_bytes": 1024,
    "spool_dropped": 0,
    "enrich_dropped": 3
  }
}
```

| Field | Meaning |
| --- | --- |
| `timestamp_ns` | agent clock at collection, nanoseconds since the UNIX epoch |
| `agent_version` | agent crate version |
| `sensors[]` | one entry per heartbeat registered on the silence monitor: `name` (`linux-ebpf`, `windows-etw`, `windows-eventlog:<target>`, …), `pulse_count` (cumulative since start) and `silent` (past its deadline without a pulse). It's the same snapshot `cli health` shows. |
| `spool_bytes` | event spool backlog awaiting upload; `0` with `--standalone` |
| `spool_dropped` | cumulative records shed by the spool's byte cap |
| `enrich_dropped` | cumulative events shed by the enrichment queue (backpressure) |

`transport`'s `heartbeat_body_is_the_documented_wire_shape` test pins this exact
shape. A change that breaks it is a change to this contract.

### Response

| Status | When | Body |
| --- | --- | --- |
| `200` | the agent is enrolled | `{"status":"ok","agentId":…,"ring":…,"lastSeen":…}` |
| `400` | the certificate subject has no usable `CN` | `{"error":…}` |
| `401` | the request carries no verified client certificate | `{"error":…}` |
| `403` | proxy authentication failed, or the agent isn't enrolled | `{"error":…}` |
| `500` | anything else | `{"error":…}` |

The agent only checks that the response parses as JSON. It reads none of the
fields.

### Server behavior today

`server/app/api/ingest/heartbeat/route.ts` updates `agent.lastSeen` and nothing
else. The beacon body is neither validated nor stored, so a `silent: true`
sensor doesn't reach the console yet. The `detect-silent-agents` cron opens a
case for every agent whose `lastSeen` is more than 5 minutes old, which is
about ten missed beacons.

### Evolving the beacon

Fields are only ever added, following the schema crate's additive-only
discipline, so the server must ignore fields it doesn't know. Renaming or
removing a field breaks every deployed agent's heartbeat, so it needs a
coordinated agent and server change.

## Agent event ingest contract

The agent's store-and-forward spool (`store::EventSpool`) drains to the control
plane in batches of `schema::Event`. This is the wire contract the server
implements (issue #553); `transport::DEFAULT_INGEST_ENDPOINT` and
`TransportClient::upload_events` are the client half.

### Paths

`POST <server>/api/v1/ingest/events`, the path compiled into the agent. The `v1`
is the API version and is kept: `server/app/api/v1/ingest/{events,heartbeat}`
re-export the handlers that live at `/api/ingest/{events,heartbeat}`, so both
spellings work and there is one implementation. The middleware treats
`/api/v1/ingest/` as public like `/api/ingest`, and nginx requires a verified
client certificate on both. (Before this, the agent's `/api/v1/...` paths matched
no route and were redirected to `/login`; that hit the heartbeat as well.)

### Request

Identity is the mTLS client certificate, forwarded by nginx as
`X-Client-Cert-Verified` and `X-Client-Cert-Subject` together with the
`X-Proxy-Secret` the server checks (`lib/agent-auth.ts`, the same authentication
as the release and content routes). `agent_id` in the body is `null` today and is
never trusted.

```json
{
  "agent_id": null,
  "events": [
    { "type": "exec", "meta": { "timestamp_ns": 1790756620574604200 }, "image_path": "/usr/bin/curl", "...": "..." }
  ]
}
```

`events` is a JSON array of `schema::Event`, internally tagged by `type` (see
`event-schema.md`). The agent sends 100 per batch
(`transport::DEFAULT_BATCH_SIZE`).

| Limit | Value | Response |
| --- | --- | --- |
| Body | 4 MiB, measured on the bytes read | `413` |
| Events per batch | 1000 | `413` |
| Body is not JSON, or `events` is not an array | | `400` |

An entry that is not an object with a string `type` is **skipped and not
counted**, rather than failing the batch: one bad event would otherwise make the
agent retry the same segment until it gives up and discards the good ones too.
nginx allows 8 MiB on the ingest locations (its default 1 MiB is below a full
batch of large events).

### Response

| Status | When | Body |
| --- | --- | --- |
| `200` | the batch was processed | `{"accepted": <n>, "batch_id": "<uuid>"}` |
| `400` / `413` | see above | `{"error": …}` |
| `401` | no verified client certificate | `{"error": …}` |
| `403` | proxy authentication failed, or the agent isn't enrolled | `{"error": …}` |
| `500` | anything else | `{"error": …}` |

`accepted` and `batch_id` are what `transport::UploadResponse` deserializes. The
agent treats any `2xx` as "delivered" and drops the spooled segment; a `5xx` or an
unparseable body is retried, other `4xx` count toward skipping the segment
(`DEFAULT_MAX_DRAIN_ATTEMPTS`).

### Server behavior today (interim)

- **Events are counted into fleet prevalence and not retained.** Each event's hash,
  image path, parent-to-child transition and DNS domain go into
  `PrevalenceSighting` (issue #76), aggregated per batch into one multi-row upsert.
  Raw telemetry belongs in the lake (`server/datalake`), which does not exist yet,
  so **an accepted event is gone once its observations are counted**, and the agent
  has already deleted its copy. Building the lake, and deciding whether to keep
  events somewhere in the meantime, is open work.
- The event's own `meta.timestamp_ns` dates the sighting, so a spool flushed after
  an outage does not look new. A missing, non-positive or more-than-a-day-ahead
  timestamp becomes the server's `now`, so an enrolled agent with a bad clock
  cannot backdate or postdate "first seen on the fleet".
- A failed counter update is logged and does not fail the request: the agent would
  retry a batch that is otherwise fine.
- `agent.lastSeen` is updated, as it is for the heartbeat and detection routes.
- Detections still go to `POST /api/ingest/detection` (one object per request).
  Nothing on the agent posts there yet.
