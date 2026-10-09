# Detection as Code

Detection content is software: versioned, reviewed, tested, and deployed like it.
Most of the pipeline already exists — this documents the contract and names the gaps.

## Already enforced
- **Versioned + reviewed**: all content lives in `rules/` (Sigma, YARA), changed only
  by PR.
- **Tested in CI**: the content workflow runs each engine's suite — every shipped
  rule must load/compile (hard failure naming the file) AND fire on a crafted
  matching sample, one per rule. Dead content cannot merge (this caught a rule that
  had been silently dead in the old iteration).
- **Loud engine validation**: unsupported constructs are rejected at load with the
  construct named, never silently skipped.

- **Rule metadata schema (#73)**: a Sigma rule is rejected at load unless it has a
  `level` (severity), at least one ATT&CK technique tag (`attack.t1059.004`), non-empty
  `falsepositives`, and sits under a known platform directory (`rules/sigma/{linux,
  windows,macos}/`): `crates/sigma/src/validate.rs`. A YARA rule must carry
  `severity`, `technique` and `falsepositives` in its `meta:` block
  (`crates/yara`, `extract_metadata`).
- **Per-rule matching and negative samples (#73)**: every shipped rule has exactly one
  crafted event that must fire it and one benign lookalike that must not
  (`crates/sigma/tests/content.rs`, `crates/yara/tests/content.rs`). For Sigma the samples
  are `<rule>.samples.json` beside the rule (ADR-0031) and the suite asserts every rule has
  its file and every file its rule; the YARA suite still asserts that sample titles equal
  the loaded rule titles. Either way a rule added, renamed or removed without its samples
  fails CI.

## Still to build
- **Ring deployment**: content ships via canary rings (`updater`/policy), with per-ring
  detection/FP telemetry and automatic halt: the same guardrails as models (gated on the
  #30 lab run).
- **Hunt graduation** (#618, gated on #61): `server/hunt` promotes a repeatedly-matching
  hunt into a draft rule PR, closing the analyst to content loop. Nothing exists on the
  hunt side yet (`server/hunt` is a README), so nothing is built for this.

### What a graduated draft will have to satisfy
Derived from what CI enforces today, so the hunt side can be built to it:

1. **A rule file that loads**: Sigma limited to the supported subset (an unsupported
   construct is a hard load error naming it), the metadata above, in the right platform
   directory. A draft that fails this fails with the file and the missing field named.
2. **A matching sample and a negative sample for it**, in `<rule>.samples.json` beside the
   rule (ADR-0031; they were Rust test tables keyed by title until then). A rule file with
   no samples file fails naming both files, so an exporter emits the pair and nothing else
   has to be edited. A hunt's own matches are a natural source of the matching sample, but
   the negative sample (a benign lookalike) has to come from an analyst or from benign
   telemetry the hunt also touched. **Still open for #618:** a hunt today queries the
   *detection* store (technique, severity, a substring of the stored alert), not
   normalised events, so it cannot be turned into a Sigma `selection` mechanically; the
   exporter can fill the metadata and the matching sample and leave the selection to the
   analyst, or wait for the raw event archive (`server/datalake`, #77).
3. **A human in the loop**: the draft enters the normal PR and review path; graduation
   never merges or ships content by itself.
