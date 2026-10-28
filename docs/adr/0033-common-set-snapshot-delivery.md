# ADR-0033: Delivering the fleet common-set snapshot: its own signed manifest, signing key and freshness bound

- **Status**: accepted 2026-10-20 as a design; the custody of the `snapshot` key is not decided (see "Owner's decisions, 2026-10-20")
- **Date**: 2026-10-14 (accepted 2026-10-20)

Proposed for the owner to accept, change or reject. The points that are the owner's to decide
(custody technology, who controls the key policy, whether to bind a tenant at enrollment) are
marked, and listed again at the end. The owner's answers are recorded in the last section.

## Context

ADR-0020 decided that the server pushes, per tenant, a **common-set snapshot** (a filter of the
image hashes seen on at least K hosts) and that the agent checks executed images against it
locally. It said the snapshot would be "one more entry in the signed content manifest"
(ADR-0016). Planning the build (`docs/detection/fleet-prevalence-snapshot-plan.md`) found that
sentence does not hold up:

1. **Signing.** A content manifest is signed offline by the `content` key, with the key held in
   custody and two approvals (ADR-0027: no private key on the control plane). A snapshot is
   derived data, rebuilt per tenant, and the replay that calibrates it assumes a 24-hour cadence.
   A human signature per tenant per day does not exist.
2. **Rings.** A content release advances `canary_0` to `prod` over seven days (ADR-0016 §4). A
   snapshot that takes a week to reach most agents is a week stale; a daily one would be a new
   content release per tenant per day.
3. **Fetching.** `apply-content-manifest` is a manual command; nothing fetches content on a
   schedule (ADR-0016, "Not covered yet"; ADR-0027 Decision 5 defers the timer).
4. **Pruning.** An agent deletes content a release no longer lists, so a snapshot would have to
   stay in every content release or vanish.

What a snapshot is worth bounds what a forged one can do. The only consumer is the "not in the
common set" evidence: a log-odds term of at most 1.0 at a time, decaying with the belief, which
by construction cannot reach the alert threshold on its own (PR #815). A forged snapshot cannot
run code and cannot cross the kill gate. It can (a) mark an attacker's hash as common, which
withholds that term for it (and, once the Rust mirror of the ML feature lands (#640), sets
`image_in_common_set`), or (b) mark nothing common, which adds the capped term to every exec:
noise, never a verdict. That is not nothing: it degrades a detection signal, and it is data the
server derives and the endpoints trust, so "what an agent loads from the control plane is signed"
should stay true.

## Decision

1. **A snapshot manifest of its own, outside the content manifest and the rings.** A new signed
   document, `SnapshotManifest`: `schema_version`, a `kind` of `common-set`, `built_at` (Unix
   seconds), `hosts_covered`, `min_hosts`, `entry_count`, the artifact's `sha256` and `size`, and
   the signature. It names exactly one artifact, the bytes of
   `docs/detection/common-set-snapshot-format.md`, which the agent writes to its fixed path
   `snapshots/common-set.bin` under the content directory. It is not part of the content
   manifest's `release_version` sequence and is not ring-keyed. Two endpoints, authenticated by
   the agent's mTLS identity like the content ones and scoped to the agent's tenant: the manifest
   and the artifact.
2. **A fourth key, `snapshot`, with one job.** It signs only `SnapshotManifest`, and an agent
   verifies a snapshot manifest against that key alone and refuses a content or release manifest
   signed by it, as ADR-0027 already separates `release` from `content` by role. Its custody
   differs on purpose: a signing-only managed key service, where the key is non-exportable and
   the control plane's snapshot job can request a signature but cannot read the key, with no
   per-signature human approval and a policy that limits the key to that job. *Owner's decision:
   which service, and who may change that policy.* This is the one place this ADR departs from
   ADR-0027 Decision 2 ("no private key on the control plane"): the control plane gets the
   ability to *request* signatures, not the key. Rotation: a rotation release signed by `release`
   (routine) or `recovery` (compromise) names a new `snapshot` key; the `snapshot` key cannot
   rotate itself or any other.
3. **Freshness and rollback on the agent, and guards on the builder, instead of rings.**
   - *Anti-rollback:* the agent refuses a manifest whose `built_at` is not later than the one in
     force, and one dated further in the future than a small clock-skew tolerance.
   - *Maximum age:* a snapshot older than `max_age` is treated as absent (the evidence is
     withheld), so a server that stops publishing, or a blocked network, cannot keep a stale set
     in force. `max_age` is calibrated in slice 6; the starting point is three cadences.
   - *Builder guards,* checked before the server asks for a signature: the size cap, `hosts_covered`
     at or above the minimum, and an `entry_count` not sharply below the previous snapshot's
     unless `hosts_covered` fell too (a truncated build). On a failure the previous snapshot stays
     served and ages out normally.
   - *Failure on the agent:* a bad signature, hash, format or `built_at` keeps the snapshot in
     force and is reported, the posture the rule directories have (a bad file never leaves a live
     agent without it).
   - *No canary progression:* a bad snapshot reaches a tenant's agents together. That is accepted
     because the effect is bounded as above and visible: the rarity counters in the health beacon
     (`rarity_applied`, `rarity_withheld`, #817) show a snapshot that suddenly marks everything
     rare or nothing. A wrong snapshot is withdrawn by publishing the next one (or an empty one:
     the evidence is withheld), which needs no offline signing step, unlike ADR-0032.
4. **A fetch loop inside `agent run`, not a timer unit or the manual command.** It polls the
   manifest at a jittered interval (a starting point is every six hours for a daily snapshot),
   downloads the artifact only when `built_at` changed, verifies, writes
   `snapshots/common-set.bin` atomically and triggers the reload the agent already performs for
   content (#814). It is gated like ADR-0027 Decision 5: not enabled in a production build until the
   `snapshot` key is provisioned; a `test-key` build can run it in the lab.
5. **What this does not change.** Content rings, signing and the manual content flow stay as
   ADR-0016 and ADR-0027 have them, for rules and models. ADR-0020's decisions (a per-tenant
   snapshot, checked locally off the capture path, weak evidence, K and the rest left to
   calibration) stand; this replaces only its sentence that the snapshot rides the content
   manifest.

## Consequences

- The trust set grows to four keys (`crates/updater/keys/snapshot.pub`, a `Role::Snapshot`). The
  key lives in a key service, so it has no air-gapped ceremony, and the routine operation of the
  three offline-held keys is untouched.
- A new signed envelope. The server builds the canonical bytes and asks the key service to sign
  them; the agent verifies. It needs golden fixtures on both sides, like the content manifest.
- Agent work: the manifest type and verification in `updater`, the `built_at` state, the fetch
  loop and the maximum age, each tested.
- **A compromised control plane can have snapshots signed** for its own tenants' agents until the
  `snapshot` key is rotated. That is the cost of automating a signature, and it is bounded by the
  analysis in Context: weak, capped, decaying evidence, no code execution, no verdict.
- **Tenant binding is open.** The agent has no tenant identifier today. The signature stops
  tampering but not misrouting: a server bug or compromise could serve tenant A's snapshot to
  tenant B's agents, which would then hold A's common-software hashes and judge rarity against the
  wrong fleet. Binding needs a tenant identifier delivered at enrollment and a `tenant_id` field
  in the manifest that the agent compares. *Owner's decision:* bind (an enrollment change), or
  rely on the server's tenant scoping and accept this.
- **What an endpoint learns.** A snapshot is the set of hashes seen on at least K hosts of that
  tenant, so an endpoint that can read it (a compromised one included) learns which software is
  common on its own fleet, and nothing about any one host. A larger K shrinks this as it shrinks
  the filter.
- Still not decided here: K, the minimum coverage, the cadence, `max_age`, the filter's
  false-positive rate and the evidence weight. They are set on lab data in slice 6.

## Alternatives considered

- **The snapshot as a content-manifest entry (ADR-0020's first wording).** Needs no new key. It
  also needs a human-approved signature per tenant per cycle, ring progression, a full content
  release per tenant per cycle, and keeping the entry listed in every release. It is workable only
  if the owner accepts a weekly snapshot signed with the normal content release: then freshness is
  up to about two weeks (a week on the rings plus a week between releases), and new software looks
  "rare" for that long. It needs nothing new for a first lab slice, but it does not meet the daily
  cadence ADR-0020's calibration assumes.
- **Sign with the existing `content` key, held online.** Rejected: it puts the key that can weaken
  every detection rule on the control plane to serve a signal worth at most one capped term.
- **Unsigned, authenticated by mTLS alone.** Defensible only if the owner judges the bound on a
  forged snapshot sufficient, and it is the smallest change. Rejected as the recommendation because
  it ends the property that everything an agent loads from the control plane is signed, and mTLS
  authenticates the agent to the server, not the data to the agent beyond the TLS session.
- **Ring-gated snapshots.** Gives a canary, and brings back the seven-day lag that rules out a
  daily snapshot. The guards and the beacon counters stand in for it.
- **A per-tenant key held by the tenant.** Out of scope; it would need key management the product
  does not have.
- **The agent asks the server per hash.** Already rejected by ADR-0020.

## Decisions needed from the owner

1. A fourth, signing-only, automated `snapshot` key (and which key service, and who controls its
   policy), or the weekly content-key path, or unsigned.
2. No canary progression for snapshots, given the builder guards, the maximum age and the beacon
   counters.
3. Tenant binding at enrollment, or not.
4. The fetch loop in `agent run` ahead of the release and content timers of ADR-0027 Decision 5,
   gated on the `snapshot` key being provisioned.

## Follow-up issues (to open if this is accepted)

1. Provision the `snapshot` key in the key service; the trust-set role and the rotation rule.
2. `SnapshotManifest`: type, canonical bytes, golden fixtures, verification and anti-rollback in
   `updater`.
3. The server's snapshot job (`getCommonHashes`, build, guards, signature request, storage) and
   the two endpoints.
4. The agent fetch loop, the `built_at` state and the maximum age.
5. Tenant binding at enrollment, if chosen.
6. Slice 6 of the plan: calibration on lab data.

## References

- ADR-0020 (what the snapshot is), ADR-0016 (content rings), ADR-0027 (the trust set), ADR-0032
  (withdrawal by corrective release); `docs/detection/common-set-snapshot-format.md`;
  `docs/detection/fleet-prevalence-snapshot-plan.md`; #76, #640, #814, #815, #817.

## Owner's decisions, 2026-10-20

Taken by the owner, who delegated the review; the reviewers of this change can contest them.

1. **A fourth, signing-only, automated `snapshot` key: accepted as the design.** Neither the
   weekly content-key path nor unsigned delivery. **Not decided:** which key service holds it and
   who may change its policy. That is the custody question of #753 / ADR-0027 and is answered
   together with it. Until then the snapshot endpoints and the fetch loop run only with the
   `test-key` feature, as Decision 4 already says; nothing here makes them available in a
   production build.
2. **No canary progression for snapshots: accepted**, with the builder guards, the maximum age
   and the beacon counters as the substitute.
3. **Tenant binding: yes, required before the fetch loop is enabled in a production build.** A
   tenant identifier delivered at enrollment and a `tenant_id` the agent compares in the manifest.
   It is not needed for the lab slices, where the server's tenant scoping is relied on. To be filed
   as its own issue (an enrollment change).
4. **The fetch loop in `agent run`, ahead of the release and content timers: accepted**, gated on
   the `snapshot` key being provisioned.

What this unblocks: the agent-side slices of #76 box 2 and the Rust mirror of #640 can be built
against the `test-key` build. What it does not unblock: shipping them to production, which waits
on the custody decision.
