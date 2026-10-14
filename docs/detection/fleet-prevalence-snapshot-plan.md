# Fleet prevalence snapshot: implementation plan (ADR-0020, #76 box 2)

ADR-0020 decisions 1 and 2 are accepted; nothing is built. This plan cuts the work into
independently mergeable PRs and lists what has to be decided first. It describes the
design as of the code on `main`; it is a plan, not a record of a decision (decisions go
in the ADR, see the last section).

## What exists

- **Server counters.** `prevalence_sightings`, one row per `(tenant, kind, key, agent)`,
  fed by every uploaded event (`server/lib/prevalence.ts`). No query yet returns "hashes
  seen on at least K hosts" or "hosts covered".
- **Rarity feature, both sides.** `crates/ml/src/features/rarity.rs` (trait `CommonSet`,
  `rarity_known`, `image_in_common_set`) and `ml/synthaea_ml/features/rarity.py`, with the
  shared golden fixture. The point-in-time reference for the snapshot semantics is
  `ml/synthaea_ml/data/common_set.py`. Nothing in the agent implements `CommonSet`.
- **Content distribution.** Signed manifest, anti-rollback, ring-scoped artifacts
  (ADR-0016). Entries are mapped to consumers by directory under the agent's content
  root, not by `type`; `agent/src/sink.rs` reloads sigma and yara on `ReloadContent`.
  The agent keeps `content_type` a plain string, so a new type does not break
  verification on old agents.
- **Enrichment.** The executed image is hashed on a worker thread
  (`agent/src/enrich_queue.rs`), after the capture-path detectors have run.
- **Correlator.** Takes numeric features and an optional ML log-likelihood ratio
  (`None` = no evidence, not benign). There is no typed evidence enum.

## Open questions that block the slices (need an owner's answer)

1. **Who signs a per-tenant snapshot, and how often?** ADR-0027 puts the content key
   offline with two approvals; a snapshot rebuilt per tenant every cadence cannot be
   signed by hand. Options: (a) amend ADR-0027 with a narrower, separately held
   snapshot-signing identity; (b) a human-approved batch signing step per cycle (slow,
   weekly at best); (c) no new signing identity, snapshot content only changes when a
   normal content release is cut. This decides the cadence the design can promise.
2. **Ring progression versus snapshot freshness.** ADR-0016 moves a release through
   rings over seven days. A snapshot that must be daily needs either an exemption for
   snapshot-only releases or a second, faster channel; neither exists.
3. **The periodic content fetch.** `apply-content-manifest` is a manual command; the
   timer is deferred (ADR-0027 Decision 5). The agent cannot receive snapshots on a
   cadence without it.
4. **Evidence delivery.** Enrichment is asynchronous to the correlator, so the hash is
   not known when the correlator first sees the exec. Either the worker feeds the
   correlator afterwards (a belief update keyed by `(ppid, comm)` like the others), or
   the lookup moves earlier on the capture path (rejected by ADR-0020: off the capture
   path). Assumed here: the worker feeds it afterwards.

## Slices

Each slice lands its tests first (CLAUDE.md), and each is useful or inert on its own.

1. **Snapshot format and builder (server).** A fixed-layout binary: header (format
   version, K, false-positive rate, hosts covered, entry count, build time), then a
   Bloom filter whose bit positions are taken from the SHA-256 itself (already uniform,
   so no hash library to keep identical across languages). A pure builder over the
   sightings of one tenant: hashes with at least K distinct hosts, `hosts_covered` as
   distinct reporting agents, capped size (the cap is part of the entry, ADR-0020).
   Golden fixture bytes in the repo, checked by the TypeScript builder and, in slice 2,
   by the Rust reader. *Accept:* the builder reproduces `common_set.py` on the same
   corpus (same members, same hosts covered).
2. **Reader (Rust, `crates/ml` next to `CommonSet`).** Parses the format, implements
   `CommonSet`, never panics on any input (robustness suite in the crate's `tests/`;
   fuzz target), rejects an unknown format version and a header that disagrees with the
   body length. Dependency direction unchanged: no sensor, no `updater`. *Accept:* the
   golden fixture from slice 1 loads and answers membership identically.
3. **Agent loader and hot reload.** `<content_root>/snapshots/common-set.bin` loaded on
   start and on `ReloadContent` into a swap-able slot; a corrupt file keeps the previous
   snapshot (or withholds the evidence), exactly like a broken rule file. New fields in
   the reload report and the IPC response (serde defaults, so the protocol stays
   compatible). *Accept:* reload with good, absent and corrupt files, each reported.
4. **Evidence into the correlator.** The enrichment worker looks up the executed
   image's hash and, when `rarity_known`, applies a weak LLR for "not in the common
   set" to the process's belief. The weight starts at a small, stated value and is
   calibrated in slice 6; it can never reach a verdict alone (a test pins this).
   Withheld (`None`) with no snapshot, too few hosts covered, or no hash. No change to
   `schema` is expected: the evidence is an LLR term and a named attribution, not a new
   event or detection source. If review finds one is needed it comes with its own
   justification.
5. **Publish path (server).** The snapshot becomes a manifest entry
   (`snapshots/common-set-<tenant>.bin`; the artifact store is keyed by path and shared
   across tenants, so the path must be tenant-unique), with K, false-positive rate and
   `hosts_covered` in the entry's `metadata`. Needs answers 1 and 2 above. The entry
   must stay in every later release or agents prune it.
6. **Lab run and calibration.** A lab scenario with at least two enrolled hosts: a binary
   common to both and a binary on one host only; assert the first is in the common set
   and the second raises the weak evidence, and that the evidence is withheld until the
   snapshot covers enough hosts. Then set K, minimum hosts covered, cadence, false-positive
   rate and the LLR weight on lab data, and record them.

Order: 1 and 2 first, then 3, 4, 5, 6. #640's Rust feature mirror needs slice 2 only; it
can start when the reader merges.

**Status.** Slices 1 and 2 are written and are one PR, #808, not two: the golden fixture is
the contract both sides test against, so splitting them would have shipped a fixture with one
reader. The format is specified in `common-set-snapshot-format.md`. That PR also settles two
details this plan left open: the filter is read by `crates/ml` (`ml::features::common_set`),
and the builder refuses to exceed its byte cap instead of truncating. Slice 3 (the agent loader and hot
reload) is its own PR: the snapshot is read from `snapshots/common-set.bin` under the content
directory, with the rule directories' posture. It deliberately leaves the IPC `ReloadContent`
response alone: that struct is `deny_unknown_fields`, so a new field would make an older client
refuse a newer agent's answer, and "serde defaults" (this plan's first wording) only protect the
other direction; the load is reported in the agent log. Slice 4 (the correlator evidence)
is a stacked PR on that one. It takes the "worker feeds the correlator afterwards" answer to
question 4: the enrichment worker, which learns the hash after the capture thread correlated the
exec, looks the hash up and adds a weak, **capped** log-odds term to the process's belief
(`CorrelationEngine::apply_rarity_evidence`). The cap is the safety property: the contribution is
at most 1.0 log-odds at a time (decaying with the belief), so with the prior it stays ~7 under
the alert threshold and rarity alone can never be a verdict, even on a build host running
thousands of freshly compiled binaries. The weight (0.35) and the minimum coverage (10 hosts)
are provisional until slice 6. Slices 5 and 6 wait on the signing and ring questions.

## Not in this plan

Decision 3 of the ADR (opt-in global k-anonymous statistics) is a product and legal
decision. The per-hash server query was rejected by the ADR and is not revisited here.

## Where the answers get recorded

Questions 1 and 2 change an accepted ADR (0027) and a design (0016): they are an
ADR-0027 amendment, not a note in this file. The calibrated numbers from slice 6 go in
an ADR-0020 follow-up and in the manifest entry, as the ADR already says.
