# ADR-0035: Adaptive posture: a signed, short-lived, heighten-only overlay per agent

- **Status**: proposed
- **Date**: 2026-10-15

## Context

#62 asks that a detection on one machine change how the rest of the pool is watched: a case
above a threshold sends a **posture overlay** to a computed set of neighbour agents (same
subnet, same identity, recent lateral peers) that lowers detection sensitivity, widens
telemetry and shortens the heartbeat, and that decays on its own. Its guardrails: posture
only ever heightens, overlays are audited like response actions, expiry is enforced by the
server, and an attacker must not be able to trigger posture floods. Its third "Done when" box
is an ADR for the overlay model; its second box says the overlay reaches neighbours "via the
policy channel".

What exists today, read from the code on 2026-10-15:

- **A policy document model, and nothing that moves it.** The `policy` crate has a signed,
  canonical-JSON `Policy` with layered overrides (ADR-0010, ADR-0011). Its `ThresholdsSection`,
  `RulesSection` and `ModelsSection` are empty structs ("real fields land with a consumer",
  `crates/policy/src/document.rs`). The server has no policy route (`server/app/api` has agents,
  auth, cases, content, corpus, cron, enrollment, graph, health, hunts, ingest, ops, prevalence,
  release, rings and v1) and the agent does not fetch a policy: the crate's own doc calls the
  wire format one "the (future) control plane and agent will exchange". So **the "policy
  channel" of the issue does not exist yet**, and this ADR has to choose one.
- **Two signed channels, both unsuited as they are.** Content (rules and models) is ring-keyed
  per tenant, not per host, signed offline with the `content` key, and moves on a cadence of
  days (ADR-0016, ADR-0027); its halt and rollback semantics (ADR-0032) are for withdrawing a
  rule, not for a per-host state that should last minutes to hours. The common-set snapshot
  (ADR-0033, `proposed`) is a manifest of its own with a signing-only key service, because it
  has the problem this ADR has: a document that must be signed automatically, without an
  offline ceremony, while ADR-0027 Decision 2 says no private key lives on the control plane.
- **Few runtime knobs to heighten.** The agent's optional captures are command-line flags
  (`--enable-tls-capture`, `--enable-readline-capture`, `--enable-dns-capture`), the health
  beacon interval defaults to 30 s, and the T0 cut-off is calibrated at training and stored with the
  model (`model_metadata.json`). The
  correlator's gate is a compile-time constant, `BAYES_THRESHOLD: f32 = 2.0`
  (`crates/correlator/src/bayes.rs`), and **it is the gate for terminating a process**: only a
  belief crossing it may kill (`agent/src/sink.rs`). #652 shows what a mistaken kill costs:
  `--enable-kill` killed NetworkManager on a stock host on that gate alone, and a lower gate
  would only make that more likely.
- **The inputs a trigger and a blast radius would use** exist in part: cases group detections
  per agent (#50), the entity graph is computed on read from detections and prevalence (#72,
  first slice), and prevalence says how many hosts ran a thing (#76).

The risks are specific to this feature. An overlay is a way to change every neighbour's
behaviour from the control plane, so a forged or replayed one, or a flood of real ones, is an
attack on the fleet: more telemetry and a lower alert cut-off on many hosts at once is a
denial of service on the agents and on the analysts. And heightening must not reach the
response gate, or a posture raised by an attacker-triggered case makes the fleet kill more.

## Decision

1. **A `PostureOverlay` document of its own, not a layer of the policy merge.** It is a
   signed, versioned document in the style of ADR-0010 (canonical JSON, a signature), but a
   separate type with its own closed schema, applied on top of the effective baseline by its own
   rule below, not through `apply_overrides`. Fields: `schema_version`, `overlay_id`, `tenant`,
   **`agent`** (one agent), `serial` (strictly increasing per agent), `reason` (the case id and
   a reason code, for the audit trail and the console), `issued_at`, **`valid_for_secs`**, and
   `heighten`. The agent refuses a document that names another agent or tenant than its mTLS
   identity, so a captured overlay cannot be replayed to a different host. Unknown fields are
   rejected (`deny_unknown_fields`, as the policy document does).
2. **Heighten-only is a property of the type and is enforced by the agent, not by trust in the
   signer.** `heighten` can only carry: a **sensitivity step** for the detection cut-offs (a
   small non-negative integer, applied as a bounded shift that can only make the T0 cut-off and
   the agent's other alert cut-offs more sensitive, within compiled-in floors; which cut-offs can
   be made adjustable is the first follow-up below); an **enable list** drawn
   from a closed enum of optional captures (the three `--enable-*` captures above); and a
   **heartbeat interval** that may only be shorter than the configured one and not below a
   compiled-in floor. There is no field that disables or loosens anything, none for `response`,
   `redaction` or `compliance_mode` (the safety-critical sub-objects of ADR-0011), and none for
   content. **No overlay may move `BAYES_THRESHOLD` or any other gate for response actions**:
   sensitivity applies to what the agent *reports*, never to what it *does*. Several live
   overlays combine by taking, per knob, the most sensitive value, and the effective value is
   clamped to the compiled-in limits.
3. **Expiry is signed and enforced on the agent, not only on the server.** An agent that loses
   its network would otherwise keep a raised posture for ever, which is the "decays on its own"
   the issue asks for failing exactly when the control plane is unreachable. The agent counts
   `valid_for_secs` from the moment it accepts the overlay, on its monotonic clock, not from a
   wall-clock `expires_at`: the lab VM's clock was two hours behind after a revert (the mTLS
   certificates read "not yet valid"), so an absolute timestamp would expire at the wrong moment
   on a skewed host. A compiled-in maximum caps `valid_for_secs` whatever the document says. An
   overlay is never extended in place: renewal is a new document with a higher `serial`; an early
   reset is a newer `serial` with an empty `heighten`. The remaining time is persisted at
   shutdown and an agent that restarts resumes at most that remaining time. The server stops
   serving an overlay once it has expired or been withdrawn, and records that.
4. **Delivery: a per-agent pull endpoint and a short loop in `agent run`.** `GET
   /api/posture`, authenticated by the agent's mTLS identity and scoped to its tenant, returns
   the current overlay for that agent or none; the agent polls it at a short jittered interval (a
   starting point is every 60 s, so a raised posture reaches a neighbour in about a minute, which
   the content cadence of days cannot do). It is not the content manifest channel, for the
   reasons in the Context, and it is not mesh gossip: the issue's own conclusion is that the
   signed channel comes first, and a gossip hint cannot carry a signature a per-agent overlay
   needs. A malformed, badly signed, replayed (`serial` not above the one in force), or
   mis-addressed document is ignored, reported, and leaves the posture as it was.
5. **Signing: a `posture` key held by a signing-only key service, the same shape as ADR-0033's
   `snapshot` key.** An overlay has to be signed at the moment a case crosses the trigger, so no
   offline ceremony can be in the loop. A fifth key, `posture`, signs only `PostureOverlay`, and
   an agent verifies overlays against it alone and refuses a content, release or snapshot
   manifest signed by it, and the reverse. The control plane can ask for a signature and cannot
   read the key; the policy of the service limits the key to the posture job. This is the same
   departure from ADR-0027 Decision 2 that ADR-0033 asks for, and it is **decided by the same
   owner decision** (see below): if ADR-0033's signing-only service is not accepted, automatic
   overlays are not possible under this design, and the fallback is analyst-approved overlays
   signed offline, which are slower and keep a human in the loop. A rotation release names a new
   `posture` key (ADR-0033's rule: it cannot rotate itself or any other). In a lab, the test key
   under the `test-key` feature signs overlays, and the endpoint and the agent loop are not
   enabled in a production build until the `posture` key is provisioned (ADR-0027 Decision 5).
6. **The server computes who is heightened, and limits it.**
   - *Trigger:* a fleet-level case (the cross-host join of #62's first box) above a severity
     and breadth threshold: a starting point is a case of `high` or above with detections on two
     or more agents, or a `critical` one. An attacker who can make detections fire on a host can
     reach this trigger, so the limits below are what bounds the effect.
   - *Targets:* the case's own hosts, plus the neighbours the entity graph names (hosts that
     share the case's identity, hosts it connected to). **Same-subnet neighbours need an address
     per agent: the graph has no subnet node and I did not find a per-agent address in what the
     server stores**, so they are out of the first slice unless that is added.
   - *Limits (starting points, calibrated in the lab):* at most a fixed number of agents per
     overlay set (50), at most one live overlay per agent per case, a cooldown after expiry
     before the same agent is heightened again for the same case unless its severity went up,
     and a per-tenant ceiling on concurrently heightened agents (a fraction of the fleet, never
     more than a fixed count). When a ceiling is reached the trigger is audited and nothing is
     sent; it never queues an unbounded backlog.
   - *Short validity:* a starting point of one hour, never above the compiled-in maximum.
7. **Audit and visibility.** Every issue, serve, application, expiry and clearing is an audit
   row, like a response action. The agent reports the overlay in force (`overlay_id`, `serial`,
   seconds left) in its health beacon, so the console shows which hosts are heightened and the
   server can check that an overlay was applied, which is the "visibly changes behaviour" half of
   #62's second box.
8. **What this does not decide or change.** ADR-0010 and ADR-0011 and their merge rules stay as
   they are; `ThresholdsSection` stays empty until a consumer exists. The content channel,
   rings and signing stay as ADR-0016, ADR-0027 and ADR-0032 have them. Windows and macOS
   behaviour is not specified here: the knobs above are the ones the Linux agent has.

## Consequences

- #62's second box becomes buildable in slices, and the order matters: the knobs first (a
  bounded sensitivity step and a runtime heartbeat interval in the agent, a runtime capture
  toggle, none of which exist yet), then the document and its verification, then the endpoint and
  loop, then the server's trigger and limits. The first slice changes nothing about response.
- The agent gains a verifier, a persisted overlay state and a poll loop, and the control plane
  gains a signing client, a table of live overlays and an endpoint. All of it is gated like the
  other automated signing (not in a production build before the key exists).
- A compromised `posture` signing service can heighten every agent of a tenant at once, up to
  the compiled-in limits and for at most the maximum validity; it cannot disable anything, move
  a response gate, or touch content. That bound is the reason Decision 2 is enforced on the
  agent.
- Heightening has a cost on the host: more telemetry and a lower cut-off mean more events and
  more false positives where the posture is raised. The per-tenant ceiling and the short validity
  are what keep that cost bounded; the right numbers need the lab.
- "Visibly changes behaviour" needs an observable: the beacon field of Decision 7, and a lab
  scenario in which a case on one VM raises a threshold or a capture on another and the change
  expires on its own, including with the control plane cut off.

## Alternatives considered

- **Ride the content manifest channel** (an overlay as a content entry). Nothing new to build
  or sign, and the ring and halt machinery exists. But content is per ring and not per host,
  signed offline on a cadence of days, and withdrawn with rollback semantics made for rules; a
  per-host state lasting an hour would be forced through all of that.
- **Server-side expiry only.** The issue asks for it, and it is simpler. But an agent cut off
  from the control plane, which is also what an attacker on a host would arrange, keeps the
  posture, and the "decays on its own" guarantee fails at the moment it matters.
- **A wall-clock `expires_at`.** Easy to audit and to display. A skewed agent clock (seen in the
  lab) turns it into an overlay that never expires or that expires before it is applied.
- **Mesh gossip between agents.** Fast and works offline, and the issue marks it post-MVP. An
  unsigned hint cannot carry the signature a per-agent overlay needs, and a signed one needs the
  same key problem solved.
- **Overlays that may also move response gates.** Would let a posture raise what the agent
  kills. Rejected: #652 shows a mistaken kill is the expensive failure, and a posture an attacker
  can trigger must not make the fleet kill more.

## Decisions needed from the owner

1. **The `posture` key and its custody**, which is ADR-0033's decision 1 asked a second time: is
   a signing-only key service the control plane can ask but not read acceptable for automatic
   signing? If ADR-0033 is accepted, this follows; if not, automatic overlays are not possible
   and #62's second box needs the analyst-approved fallback.
2. **Whether overlays may carry a detection-sensitivity step at all**, given the cost in false
   positives, or only widened telemetry and a shorter heartbeat. The latter is the conservative
   first slice.
3. **The trigger and the limits** (the severity and breadth of a case, the set size, the
   per-tenant ceiling, the validity and the cooldown): the numbers above are starting points,
   not conclusions.
4. **Per-host addressing** (one signed document per agent, Decision 1) against one document per
   target set with an agent list: the former keeps a captured overlay from being replayed to
   another host; the latter signs once for many.

## Follow-up issues (to open if this is accepted)

- Agent: a bounded sensitivity step, a runtime heartbeat interval and a runtime capture toggle,
  with their compiled-in floors (no overlay yet).
- `policy` crate: `PostureOverlay`, its verification against the `posture` key, anti-rollback and
  the agent-side expiry on a monotonic clock.
- Server: `GET /api/posture`, the table of live overlays, the audit rows, and the trigger and
  limits of Decision 6.
- A lab scenario: a case on one VM heightens another VM, the change is visible in the beacon,
  and it expires on its own, with and without the control plane.

## References

- #62; #72 (entity graph), #76 (prevalence), #50 (case grouping), #652 (`--enable-kill` on
  BAYES).
- ADR-0010 and ADR-0011 (policy model and override granularity), ADR-0016 (content rings),
  ADR-0027 (production signing keys), ADR-0032 (content withdrawal), ADR-0033 (common-set
  snapshot delivery, whose signing decision this one shares).
