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
  (`crates/sigma/tests/content.rs`, `crates/yara/tests/content.rs`). The suites assert the
  sample titles equal the loaded rule titles, so a rule added, renamed or removed without
  its samples fails CI.

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
2. **A matching sample and a negative sample for it.** Today these are Rust test data
   keyed by rule title, *not* files beside the rule, so a rule file alone cannot pass the
   suites: it fails with "sample titles must exactly match the loaded rule titles". For
   graduation to emit a complete draft, either it also emits the two sample entries into
   those test tables, or the samples move into data files next to each rule that the
   suites read. That is a design decision for #618 before any exporter is written; a
   hunt's own matches are a natural source of the matching sample, but the negative
   sample (a benign lookalike) has to come from an analyst or from benign telemetry the
   hunt also touched.
3. **A human in the loop**: the draft enters the normal PR and review path; graduation
   never merges or ships content by itself.
