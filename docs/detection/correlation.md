# Correlation

Building cases from detections: temporal windows, entity linking, Bayesian LLR scoring,
and case lifecycle.

The `correlator` crate keeps short-term memory (`EventBus`, a time-evicted window of
recent events) and turns it into two things: **co-occurrence alerts** (layer 6 — spawn
then connect, connect then write, respawn then beacon, ...) and a **per-entity belief**
that a process is compromised (layer 4).

## The belief state

Belief is tracked per `(ppid, comm)` rather than per pid, so it survives a respawn
(`fork`+`exec` is a new pid, same identity). It is a single log-odds number, prior
`-4.6` (~1% compromise), decaying back toward the prior over ~5 min of inactivity.
Two sources move it:

| Source | Tier | What it reads | Status |
| --- | --- | --- | --- |
| Per-feature Bayesian LLRs | T1 | `BehaviorVector` (has_connect, exec→connect timing, suspicious path, connect count, external dest, ...), summed under a naive-independence assumption | built — `bayes::log_likelihood_ratio`, calibrated on the NjRAT capture (n=97/23, 2026-08-28) |
| Correlation ML score | T2 | the 8-feature window vector (`ml::features::correlation`) scored by an Isolation Forest | scorer built (`ml::CorrelationScorer`); fusion seam + trained model pending |

An alert fires when `log_odds` crosses `+2.0` (~88%), once per crossing.

## T2 — the correlation scorer

A second, complementary ML signal to the T0 cmdline scorer, **never merged into one
model** (2026-08-27): the two vectors differ in when they are available (a cmdline is
ready the instant an `Exec` arrives; this one only once the window holds several events
for the pid) and in statistical nature (counts and spans vs text shape).

The 8 features, per pid over the current window: `spawn_count`, `connect_count`,
`filewrite_count`, `unique_daddr_count`, `unique_dport_count`, `has_full_chain`,
`span_s`, `event_count`. Definitions are a Rust/Python parity seam
(`ml::features::correlation` ↔ `synthaea_ml/features/correlation.py`).

`ml::CorrelationScorer` loads the model from the update channel (never embedded —
ADR-0002), runs it through `ort`, and pairs the score with a per-feature attribution
from the parsed forest (a T2 detection is never a bare number, same rule as T0).

- **Gate**: a window with fewer than `MIN_EVENT_COUNT` (3) events for the pid is nearly
  all zeros and carries no signal — the scorer returns `None` and the model is not run.
- **No standalone threshold in v1**: T2 does not alert. `score_to_llr` maps the
  `decision_function` output (negative = anomalous) to a log-odds term the correlator
  adds to the belief alongside the T1 LLRs. The two tiers still alert independently
  (OR) — T2 only makes T1 quicker to believe.

### Calibration status

`score_to_llr` is **provisional**. Its slope and clamps are placeholders; the real
values come from the pipeline's LLR calibration on a benign multi-event baseline
(the same step that regenerates `bayes::log_likelihood_ratio`), which needs the
capture campaign that does not exist yet (`ml/synthaea_ml/data/correlation_train.jsonl`,
issue #44). Until then T2 can only ever contribute to a belief, never alert alone, and
the clamps bound its influence: `[-1.0, +3.0]` log-odds, asymmetric because a behaviour
model exonerates far more weakly than it accuses.

### Wiring seam (pending)

`ml` depends on `correlator` (for `EventBus`); the reverse edge would be a dependency
cycle, so the correlator cannot call the scorer directly. The intended wiring is
"compute in `ml`, inject through `correlator`": the agent runs `CorrelationScorer`
against the engine's bus and hands the LLR back through a small `correlator` API
(a score-provider trait on the engine, or an extra term on the belief update). That
seam is not implemented — see the T2 handoff note.

## Web request and web-server shell (T1505.003)

`Event::HttpRequest` (a request from a web access log that matched a detection
signature, #478 / ADR-0022) has no pid, so it cannot join the pid-keyed rules above. It
is pushed to the bus and paired **by time** with a shell exec whose parent is a web
server (`nginx`, `apache2`, `httpd`, `lighttpd`, `php-cgi`, `php-fpm*`): one alert per
shell, naming the closest request (signature, method and path, status, client, and the
matched parameter's *name*, never its value). Either event can arrive first: the log
line is written when the request ends, after the shell it caused, and read a moment
later. The engine returns before every pid-keyed step for an `HttpRequest`, so it never
creates a belief for a pid-0 pseudo-process.

This is co-occurrence on one host, not proof of causality: a log line names no process,
so a probe and an unrelated shell under php-fpm in the same window pair. The stateless
`rules` T1059 alert on the shell itself still fires on its own; this one adds the
request that likely caused it.

## Parity fixtures

- `ml/tests/fixtures/features_golden.jsonl` — the vector (Python defines the model's
  input space; Rust must reproduce it).
- `ml/tests/fixtures/correlation_scorer_golden.jsonl` — the score the shipped `ort`
  runtime computes from a window of events, including the gate. Regenerate both (and
  retrain the model) only on a deliberate definition change, never to green a red test.
