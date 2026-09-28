# Architecture Overview

The system backbone: what the pieces are, which plane every byte travels on, and
the invariants that future changes must not break. Entry point for the other
architecture documents ([agent](agent.md), [control plane](control-plane.md),
[event schema](event-schema.md), [threat model](threat-model.md)). Status
markers are honest: **live** means code on `main`, **planned** means designed
but not built.

## The three systems

| System | Where | Stack | Status |
| --- | --- | --- | --- |
| Endpoint agent | workspace root (`agent/`, `watchdog/`, `crates/*`) | Rust | live (Linux eBPF + Windows ETW; macOS at M5) |
| Control plane | `server/` | Next.js + PostgreSQL (ADR-0001) | planned (README skeletons; ingest API contract already fixed by `transport`, below) |
| ML training | `ml/` | Python (pure-stdlib features; sklearn/ONNX for training/export) | live (trains + exports; on-device inference in `crates/ml` awaits pipeline wiring) |

## Agent layering

The dependency-direction rules (`tools/check-deps.py`, CI-enforced) *are* the
architecture — a layered system where the layers are crates and the compiler
enforces the arrows:

```text
            ┌─────────────────────────────────────────────┐
composition │            agent / watchdog / cli           │  may depend on everything;
   roots    │  (constructor injection, all cfg(target_os))│  the ONLY place two tiers meet
            └──────┬───────────────┬──────────────┬───────┘
            ┌──────▼──────┐ ┌──────▼───────┐ ┌────▼─────────────┐
  adapters/ │  sensors/*  │ │  detection   │ │ leaf services    │
  services  │ (linux eBPF,│ │ rules, sigma,│ │ store, sinks,    │
            │ audit, net- │ │ correlator,  │ │ transport, res-  │
            │ link, ETW,  │ │ ml, yara,    │ │ ponse, enrich*,  │
            │ eventlog…)  │ │ + enrich*    │ │ ipc, updater…    │
            └──────┬──────┘ └──────┬───────┘ └────┬─────────────┘
            ┌──────▼───────────────▼──────────────▼───────┐
 contracts  │              schema  ·  policy              │  semi-frozen, dependency-light
            └─────────────────────────────────────────────┘
```

- `schema` is the platform boundary: event types plus the `Sensor`/`EventSink`
  contract. Sensors normalize *into* it; detection consumes *only* it.
- Sensor crates depend only on `schema` (+ their own wire crate). Detection
  crates never depend on a sensor. Platform-specific code (`cfg(target_os)`)
  exists only inside `crates/sensors/*` and the binaries.
- The binaries are the composition points: the one place a `policy` type may be
  converted into a sensor's config type, a spool handed to a transport, a
  platform kill-callback injected into `response`.

## The planes

Three kinds of traffic, deliberately separated:

**Telemetry (data plane), live end to end on-device, server side planned:**

```text
kernel ──► sensor ──► DetectionSink ──► engines (rules/sigma/correlator/yara)
                          │                         │
                          │                         └─► alerts.ndjson (+ response)
                          ├─► enrich worker ──► events.jsonl
                          │        └──────────► EventSpool ──► transport ──► POST /api/v1/ingest/events
                          └─► progress counter (watchdog heartbeat)
```

Store-and-forward with at-least-once delivery: the spool's two-phase
drain/ack survives crashes and outages, sheds-oldest past its byte cap
(counted), and skips a permanently-rejected poison segment rather than
blocking newer data. Detection is entirely local — nothing in the alert path
waits on the network, ever.

**Health (control plane, agent → server):** `schema::HealthBeacon` — sensor
silence status, spool depth, shed counters — emitted on its own cadence and
POSTed to `/api/v1/ingest/heartbeat`, deliberately *not* an `Event` variant so
control-plane traffic never pollutes the telemetry pipeline. An agent that
stops beaconing is as suspicious as one that stops sending events.

**Command (control plane, server → agent), planned:** enrollment (mTLS client
certs — the `transport` client already speaks it), policy distribution
(`policy` crate types are the shared vocabulary; ADR-0010/0011), and content
updates (Sigma/YARA bundles, ML models — fail-closed parsing, ADR-0002/0009).
Nothing downloads yet; the seams exist so nothing needs redesign when it does.

## Kill resistance (defense in depth)

```text
service manager (systemd / OpenRC / SCM / launchd)   restarts ↓ on death
        └── watchdog  ── supervises, binary-pins, drift-detects ↓
                └── agent ── detects its own silencing (#71), protects its files
```

The watchdog deliberately depends on **zero** workspace crates — the
supervisor shares no code, and therefore no failure modes, with what it
supervises. Its per-platform install arms share one hardening gate
(world-writable refusal, owner/mode normalization — `service::resolve_paths`).

## Invariants (the "avoid later problems" list)

1. **Never block capture.** The sensor drain thread runs in-memory detection
   only; all file/crypto/network I/O lives on worker threads behind bounded,
   shed-and-count queues. Anything added to `on_event` must obey this.
2. **Bounded and observable state.** Every long-lived map/queue has a cap, an
   eviction policy, and a counter for what it shed. An unbounded collection
   keyed by attacker-influenceable input is a memory-DoS bug.
3. **Schema changes are versioned, never silent.** Serialization-visible
   change ⇒ `SCHEMA_VERSION` bump + full golden-fixture snapshot
   (see [event-schema.md](event-schema.md)).
4. **Detection never fabricates.** Failed attribution is `Unknown`/`None`,
   not a plausible guess; name-keyed exclusions are gated on evidence.
5. **The dependency arrows only point down.** New crate ⇒ classified in
   `tools/check-deps.py` in the same change.
6. **Offline is nominal.** Every server-facing path degrades to local
   operation (spool, retry, backoff) and recovers without operator action.
7. **Content fails closed, telemetry fails open.** Broken shipped rules or
   models are a hard error; a broken *event* is skipped and counted.
8. **The watchdog stays dependency-free.** Sharing convenience code with the
   agent trades away the isolation that justifies its existence.

## How it is verified

Every layer above has a matching enforcement mechanism — the style doc's rule
("if a rule matters and nothing enforces it, the fix is to add enforcement")
applied to the architecture itself:

- **The whole matrix in one command**: `tools/gauntlet.sh` (fmt, dependency
  direction, clippy on host + Linux target + the Windows sensor crates, all
  tests, cargo-deny, the strict docs build), with an opt-in pre-push hook.
  CI runs the same jobs on every push and PR and is the gate (#318).
- **Contracts**: golden fixtures pin every `Event` variant per
  `SCHEMA_VERSION`; `v1_compat` pins backward reads; the ML feature vectors are
  parity-tested Rust↔Python against shared fixtures (ADR-0002).
- **Hostile input**: the byte parsers carry never-panic robustness suites, and
  the kernel-socket decoders coverage-guided fuzz targets (`fuzz/`).
- **Content**: shipped Sigma/YARA must parse *and fire* on crafted samples —
  unfireable content fails the suite.
- **Reality**: the lab (`lab/`, Vagrant/Hyper-V) validates what unit tests
  cannot honestly claim — real eBPF verifiers, SELinux, Windows event
  channels, service installs.

See [testing.md](../development/testing.md) for the full map.

## Where decisions live

Cross-cutting choices get an ADR (`docs/adr/`) at the time they're made:
server stack (0001), ML delivery (0002), auth (0003), the Windows event
sources (0004–0007), correlation features (0008), model↔scenario binding
(0009), the shared policy model (0010–0011), driver language (0012), agent
config (0013), self-protection stance (0014). This document describes the
result; the ADRs record the why.
