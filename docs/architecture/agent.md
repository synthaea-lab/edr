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
carries the control-plane URL, its mTLS material and CA, and the storage/ipc/resource
sections; `agent run` uploads to `server.control_plane_url` by default, presenting
`server.mtls_cert`/`mtls_key` and trusting only `server.ca_cert` when it is set, with
`--server` as an override (a server named by hand never gets the configured client
certificate) and `--standalone` to upload nothing — #658.)

- `commands/common.rs` — the platform-independent spine of `run`:
  optional transport (spool + upload thread, to the configured control plane unless
  `--standalone`), the `DetectionSink`
  (spooling into it when transport is on), the operator banner, the
  progress-backed liveness heartbeat (#102). A new pipeline stage lands here
  once, not per platform.
- `commands/linux.rs` / `commands/windows.rs` — sensor selection (eBPF with
  audit fallback; ETW + eventlog), and platform-only wiring: response hooks
  (#25, Linux-first), silence monitors (#71), netlink/journal pollers, the
  opt-in uprobes sensor (`--enable-tls-capture` / `--enable-readline-capture`,
  #90 — inert on Windows like the response flags), protected-resource guard,
  kill-loudness.
- `captures.rs` (Linux) — the optional uprobe captures as a set that can only be **widened** at run
  time (`CaptureSet`: the configured captures plus whatever is widened, never fewer than
  configured). A `uprobes-supervisor` thread in `commands/linux.rs` follows it: the uprobes sensor
  reads its config once, so a change **restarts** it, which leaves a gap in capture while the eBPF
  object reloads; the sensor's heartbeat is watched by the silence monitor only while it runs.
  Nothing widens the set yet (ADR-0035, #62 box 2: an overlay will).

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

Each alert is also printed on stderr as an `[ALERT]` line. By default, that line
carries only the technique and the `pid=… comm=…` the rule message starts with,
followed by `(details in alerts.ndjson)`. The message body is left out because
rules put the command line there, and event payloads never reach the terminal at
default verbosity (#319). `run --alert-details` prints the whole message. The
file and `cli detections` always get the whole message, redacted (ADR-0034).

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
| `<alerts>/../spool/` | store-and-forward segments awaiting upload (not with `--standalone`) |

## Degraded modes (each one deliberate, logged, and counted)

- **Server unreachable / `--standalone`:** fully local; events spool (or are
  simply not spooled); alerts and detection unaffected. Reconnect drains the
  backlog, at-least-once.
- **Upload cannot be set up (unreadable client certificate or key, a passphrase-protected
  key, a missing CA):** with `server.offline_fallback` on (the default) the agent runs and
  detects locally, logs `UPLOAD DISABLED` and writes an `UPLOAD-DISABLED` alert; with it off it
  stops at start-up. Dying would turn a certificate problem into no detection and, under
  the watchdog's probation, a rolled-back and banned release (#658).
- **eBPF unavailable (old kernel, lockdown):** audit-fallback sensor, reduced
  fidelity, recorded in capabilities.
- **Enrichment/scan overload:** shed-and-count; a lost enrichment is a lost
  hash on one record, never a lost detection and never stalled capture.
- **Sensor goes silent:** the silence monitor (#71) alerts locally and marks
  the sensor in the health beacon; the watchdog restarts a hung process via
  the progress heartbeat (#102). The eBPF sensor pulses when it handles events
  (it has no forced tick), with a 120 s deadline, so on a host where nothing
  happens for two minutes it can read silent: indistinguishable from a stalled
  sensor, by design (`silence.rs`); in practice the agent's own execs and opens
  keep it alive. The journal sensor pulses on **every line `journalctl` delivers**,
  not only the allowlisted ones, and the agent writes its own line into journald
  every 30 s (`SYSLOG_IDENTIFIER=synthaea-agent-canary`, `journalctl -t
  synthaea-agent-canary`), so an idle host stays healthy while a stopped journald
  or a stuck `journalctl` still reads silent at the 120 s deadline. Before that
  (until #846) only auth and unit records pulsed it: on an idle lab VM,
  2026-10-14, `linux-journal` went silent, the host showed `Degraded` and
  recovered when the next login wrote to the journal.
- **A flood of file opens (kernel ring buffer full):** the eBPF sensor drops open
  events when its ring buffer fills, logging `ring buffer full, dropping open
  event` (not counted in the health beacon, so the control plane cannot see it).
  Every detection built on opens loses events with them, canary touches included.
  Measured 2026-10-14 on a 2 vCPU Fedora 44 VM, agent from `main`, one canary
  touch per `cat`: 20 of 20 touches alerted on a quiet host (twice), 9 of 20 while
  a `grep -r` read `/usr` and `/etc` (29,402 drops logged); an earlier burst of 8,000
  execs also cost 2 of 4. The canary cooldown plays no part (it is keyed by canary and
  pid). One run per case on one VM, not a distribution.
- **Parent-image cache full (#783):** eviction asks `/proc` and drops entries of exited
  processes before idle live ones, so an idle long-lived parent keeps resolving
  during a flood. Measured 2026-10-14 (same VM, 240,000 execs in about 257 s, builds
  alternated, two runs each): children of an idle long-lived parent got no
  `parent_image_path` in all 8 observed with the build before #801, and
  `/usr/bin/bash` in all 4 observed after; the agent's CPU time was the same within about 2 %.
  The capture file lost some of the 5 marker children per run, so few were observed.
- **Sigma/YARA content absent:** engines disabled, agent runs; content present
  but broken: loud failure (fail-closed, overview invariant 7).

## Resource budgets

Hashing is capped (`enrich::MAX_HASH_BYTES`), scans budgeted
(`yara::MAX_SCAN_BYTES` + queue depth), TLS/readline capture rate-limited per
process (uprobes budget trackers), the spool byte-capped, detection maps
LRU-bounded (`store::BoundedMap`). The pattern for anything new: a cap, an
eviction policy, and a counter — see overview invariant 2.
