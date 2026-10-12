# ADR-0020: Getting fleet prevalence to the agent, and out of the tenant

- **Status**: accepted for decisions 1 and 2; decision 3 is not decided (see below)
- **Date**: 2026-09-30 (accepted 2026-10-09)

## Context

Issue #76 (Layer 5) counts, per tenant, how many hosts have shown a hash, image
path, parent-to-child transition or domain, and since when. The server side is
built (counters fed by every uploaded event, a triage line on the case page, a
retention job). Three items in the issue still cross a boundary and need a
decision before code:

1. **"First execution on fleet" as correlator evidence.** The correlator runs on the
   device, on the capture path. The counters live on the server.
2. **The rarity feature in per-site recalibration.** T0/T1 features exist on both
   sides of a parity seam (`crates/ml`, `ml/`). A feature the device cannot compute
   cannot be a model input.
3. **Opt-in, aggregated, k-anonymous global statistics.** Data that leaves a tenant.

Constraints already fixed: detection state on the device is bounded and observable;
the capture thread must not wait on the network; the agent works offline
(`offline_fallback`); content already reaches agents through signed, ring-scoped
manifests (ADR-0016); per-tenant data stays per-tenant (`server/prevalence/README.md`).

## Decision

### 1. Push a snapshot; do not query per event

The server publishes, per tenant, a **common-set snapshot**: a compact set of the
hashes seen on at least K hosts of that tenant (Bloom or cuckoo filter, false-positive
rate stated in the manifest), as one more entry in the signed content manifest
(ADR-0016). The agent checks executed images against it locally, off the capture
path, at the point enrichment already hashes them.

The evidence it yields is **"not in the common set"** (rare or new on this fleet),
a weak input to the correlator's belief like any other co-occurrence signal, never an
alert on its own. It is deliberately weaker than "first seen on the fleet": a filter
cannot say *never*, and a fleet that just enrolled has an empty snapshot, so the
evidence is withheld until a snapshot exists and covers at least a stated number of
hosts (otherwise every binary on a new fleet looks rare).

*Rejected: the agent asks the server about each new hash.* It puts a network round
trip and a server dependency on every first execution, fails offline, and sends the
server a live feed of what every host runs. It is exact ("never seen" is real), which
is its one advantage, and the per-hash cost is what rules it out at fleet scale.

### 2. The ML feature is computed from the same snapshot

Whatever the model consumes must be derivable on the device, so the rarity feature is
defined over the snapshot, as two numbers: `rarity_known` (a snapshot exists, covers
enough hosts, and the event carries a hash) and `image_in_common_set`, an ordinal rather
than a host count. A tiered pair of filters (K1, K2) would give three levels if two prove
too coarse. Training data must use **point-in-time** values (the snapshot as of the event,
not today's counters), or the model learns from the future. A site corpus that carries
agent id, time and image hash can supply them by itself (`synthaea_ml/data/common_set.py`,
#640), so the feature does not wait for the telemetry lake; the lake (`server/datalake`,
#77) is only needed to train on fleet history. The Rust mirror takes the same two inputs
and comes with a shared fixture on both sides of the parity seam like every other feature.

**Left to calibration, not fixed here:** K (how many hosts make a hash "common"), the
minimum number of hosts a snapshot must cover before the evidence counts, the snapshot
cadence (24 h in the Python replay) and the filter's false-positive rate. They are set on
lab data and recorded where they are used (the manifest entry, the model record), not in
this ADR.

### 3. Global statistics: hashes only, k across tenants, opt-in, not built, not decided

If built: only `sha256` (a public property of a file, unlike a path or domain, which
identify an organisation), only keys seen in at least k distinct tenants, only as
aggregates with no tenant attribution, and only for tenants that opted in by an
explicit setting. k, the opt-in mechanism and the contract wording are product and
legal decisions, not engineering ones, and this ADR does not pick them.

## Consequences

- No per-event server dependency and no new agent-to-server channel: the snapshot
  rides the existing manifest, ring and anti-rollback machinery.
- The evidence is delayed by the snapshot cadence and has a false-positive rate, so
  its weight in the belief must be calibrated, not assumed.
- Snapshot size grows with the fleet's distinct common hashes; a cap and a K that keeps
  it small are part of the design of the entry.
- Item 2 waits on item 1 for the agent side only; the Python side and the recalibration
  run need neither the lake nor the agent. Item 3 waits on a decision that is not ours
  to make: this ADR does not accept it.
- The server counters stay the source of truth; the snapshot is derived from them and
  can be rebuilt.
