# Agent

The agent process in detail: how the pipeline is composed, which thread does
what, and the degraded modes. The system-level view and the invariants live in
[overview.md](overview.md); this document is the map of `agent/` itself.

## Composition

`main.rs` loads the install configuration **first** (`agent.toml` via
`config::load`, ADR-0013 — fail-fast on missing/invalid, discovery order in
`crates/config`; it sets the log level, `RUST_LOG` still overrides), then
parses the CLI and dispatches to `commands/` — the only module tree with
`cfg(target_os)`. Composition is plain constructor injection, checked at
compile time; there is no registry or DI framework. (The config file also
carries the control-plane URL and storage/ipc/resource sections; today's
upload path is still driven by the `--server` flag — aligning the two is part
of #314.)

- `commands/common.rs` — the platform-independent spine of `run`:
  optional transport (spool + upload thread, `--server`), the `DetectionSink`
  (spooling into it when transport is on), the operator banner, the
  progress-backed liveness heartbeat (#102). A new pipeline stage lands here
  once, not per platform.
- `commands/linux.rs` / `commands/windows.rs` — sensor selection (eBPF with
  audit fallback; ETW + eventlog), and platform-only wiring: response hooks
  (#25, Linux-first), silence monitors (#71), netlink/journal pollers, the
  opt-in uprobes sensor (`--enable-tls-capture` / `--enable-readline-capture`,
  #90 — inert on Windows like the response flags), protected-resource guard,
  kill-loudness.

Sink composition is decorator-style, matching the trait design
(`EventSink::on_event(&self)`): `PulsingSink(ProtectedResourceGuard(DetectionSink))`
on Linux; supplementary sensors share the same sink through `Arc`.

## Threading model

One rule governs it (overview invariant 1: never block capture), and every
thread exists to serve it:

| Thread | Owns | Blocking I/O allowed |
| --- | --- | --- |
| sensor drain (per sensor) | in-memory engines: rules, sigma, correlator dispatch | **no** |
| uprobes drain (opt-in) | TLS/readline capture: budget + allowlist + redaction, then the same sink | **no** |
| `enrich` worker | SHA-256 + signature (budgeted), `--events` file append (when given), spool append | yes |
| `yara-scan` worker | budgeted content scans, quarantine (#25) | yes |
| `transport-upload` | spool drain → batched POST, backoff | yes |
| heartbeat writer | progress-counter file the watchdog polls | yes |
| silence monitor / health beacon | deadline checks; beacon log + heartbeat POST | yes |
| `kill_loudness` watcher (Linux) | signal attribution before dying (#71) | yes |

Hand-offs into workers are bounded channels with non-blocking sends —
overflow sheds and counts (`EnrichQueue`, `yara::ScanQueue`, the spool's byte
cap). The capture thread never learns the network exists.

## The detection sink

`sink::DetectionSink` dispatches each event to: stateless + stateful rules,
the Sigma engine (when content is present — absent content is not an error,
*broken* content is), the correlator (co-occurrence + Bayesian belief, which
is also where response verdicts originate), and hands the event to the enrich
worker for hashing, raw logging, and spooling. Alerts append to
`alerts.ndjson` via a shared writer; the progress counter increments only
after full processing, so the watchdog's heartbeat measures real forward
progress, not scheduling.

Response (#25) is injected, not built in: `enable_response` hands the sink a
policy plus an OS kill callback. A platform that never calls it is
indistinguishable from policy-disabled — observe-only either way.

## Files on disk (derived from `--alerts`; the raw event log is the one opt-in flag)

| Path | What |
| --- | --- |
| `alerts.ndjson` | one alert per line (rules/sigma/yara/correlation/response) |
| `--events <path>` | every normalized event, enriched (raw capture for ML/lab). Off unless the flag is given: the file grows without bound, so the packaged service never writes it (#559) |
| `<alerts>/../heartbeat` | progress counter for the watchdog (#102) |
| `<alerts>/../quarantine/` | quarantined payloads (#25) |
| `<alerts>/../spool/` | store-and-forward segments awaiting upload (`--server`) |

## Degraded modes (each one deliberate, logged, and counted)

- **Server unreachable / no `--server`:** fully local; events spool (or are
  simply not spooled); alerts and detection unaffected. Reconnect drains the
  backlog, at-least-once.
- **eBPF unavailable (old kernel, lockdown):** audit-fallback sensor, reduced
  fidelity, recorded in capabilities.
- **Enrichment/scan overload:** shed-and-count; a lost enrichment is a lost
  hash on one record, never a lost detection and never stalled capture.
- **Sensor goes silent:** the silence monitor (#71) alerts locally and marks
  the sensor in the health beacon; the watchdog restarts a hung process via
  the progress heartbeat (#102).
- **Sigma/YARA content absent:** engines disabled, agent runs; content present
  but broken: loud failure (fail-closed, overview invariant 7).

## Resource budgets

Hashing is capped (`enrich::MAX_HASH_BYTES`), scans budgeted
(`yara::MAX_SCAN_BYTES` + queue depth), TLS/readline capture rate-limited per
process (uprobes budget trackers), the spool byte-capped, detection maps
LRU-bounded (`store::BoundedMap`). The pattern for anything new: a cap, an
eviction policy, and a counter — see overview invariant 2.
