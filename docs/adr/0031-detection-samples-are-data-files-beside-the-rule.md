# ADR-0031: A rule's samples are a data file beside it

- **Status**: proposed
- **Date**: 2026-10-08

## Context

CI (`crates/sigma/tests/content.rs`) requires every shipped Sigma rule to fire on a matching
sample and to ignore a benign lookalike (issue #73). Those samples were Rust test data, two
tables keyed by the rule's title, and a check that the titles match the loaded rules exactly.
So a rule file alone could not pass the suites: adding or renaming a rule meant editing Rust
in a second place, and a tool that wants to emit a complete draft rule (the hunt graduation of
#618, `docs/detection/detection-as-code.md`) would have had to write into test source.

## Decision

1. **`<rule>.yml` has a sibling `<rule>.samples.json`** with exactly two events, `matching`
   and `non_matching` (`image`, `cmdline`, and an optional `note` saying which boundary the
   negative sample probes). Unknown fields and a missing half are refused.
2. **The pairing is checked, not the title.** A rule without its samples file fails naming both
   files (dead content cannot merge); a samples file without a rule fails as stale. One rule
   per file was already the convention (`every_shipped_rule_loads`).
3. **Data, not code.** JSON rather than YAML, so the engine's own loader, which reads every
   `.yml`/`.yaml` under `rules/sigma`, never mistakes a sample for a rule.
4. **Sigma only, for now.** The YARA suite keeps its tables; the same move is open there.
5. **Unchanged:** the samples exercise `ExecEvent` only, as the rules do; adding another event
   type is its own change.

## Consequences

- A tool, or an analyst, adds a rule by adding two files in the same directory; no Rust edit.
- The migration moved the eight existing samples verbatim (the "near miss" comments became
  `note` fields), and the old tables and the title-matching helper are gone: one source.
- The negative sample still needs a human or benign telemetry. Producing it from a hunt is
  not solved here; this only removes the Rust-table obstacle (#618).
- `.github/workflows/content.yml` already triggers on `rules/**`, so a sample change runs the suite.
