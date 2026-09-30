# Control Plane

Server-side design: enrollment/PKI, ingest, detection store, policy and content
distribution, case queries, console. Technology choices recorded here once made.

## Agent heartbeat contract

Every agent running with `--server` tells the control plane it is alive by
sending its health beacon. The control plane's silent-agent detection relies
on that signal and nothing else: an agent that stops beaconing gets flagged
the same way as one that stops sending events.

### Request

`POST <server>/api/ingest/heartbeat`, with a JSON body
(`transport::DEFAULT_HEARTBEAT_ENDPOINT`, sent by `TransportClient::send_heartbeat`;
served by `server/app/api/ingest/heartbeat/route.ts`). The `/api/ingest/`
prefix is load-bearing: it's what nginx's mTLS `location` covers and what the
server middleware lets through without a console session. Anything else gets
redirected to `/login`. `transport`'s `the_heartbeat_endpoint_is_a_real_server_route`
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
| `spool_bytes` | event spool backlog awaiting upload; `0` without `--server` |
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
