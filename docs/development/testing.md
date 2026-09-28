# Testing

What kind of test goes where, and how to run everything. The style rules for
tests (naming after behavior, public-API-only, `schema::fixtures` baselines)
live in [code-style.md](code-style.md#tests); this page is the map.

## The one command

```bash
tools/gauntlet.sh          # fmt, deps, clippy (host + linux target + windows sensor crates), tests, cargo-deny, docs
tools/gauntlet.sh --fast   # skips the cross-target and docs passes
```

CI (`ci.yml`) runs on every push and pull request and is the gate (#318).
The gauntlet runs the same checks on one machine, so a failure shows up before
the push instead of on the PR: run it before pushing, or opt into the pre-push
hook with `git config core.hooksPath tools/hooks`.

## Test taxonomy

| Kind | Where | What it pins |
| --- | --- | --- |
| Unit | `#[cfg(test)] mod tests` next to the code | one behavior, named after it |
| Golden fixtures | `crates/schema/tests/golden.rs` + `tests/fixtures/v<N>/` | serialization: every `Event` variant, one full snapshot per `SCHEMA_VERSION`, files never edited (see [event-schema.md](../architecture/event-schema.md)) |
| Back-compat | `crates/schema/tests/v1_compat.rs` | frozen v1 payloads still deserialize under current types |
| Content suites | `crates/sigma/tests/content.rs`, yara tests | every shipped rule parses **and fires** on a crafted sample — unfireable content is dead content and fails |
| ML parity | `crates/ml/tests/`, `ml/tests/` (same fixture vectors) | Rust and Python feature extraction cannot drift (ADR-0002; known gaps tracked in #109) |
| Robustness | `<crate>/tests/robustness.rs` | byte parsers never panic: deterministic seeded corpus, every truncation of a valid input, length-lying attributes |
| Fuzzing | `fuzz/` (workspace-excluded) | the same never-panic contract, coverage-guided — `cargo +nightly fuzz run audit_parse` (see `fuzz/README.md` for the crash → `tmin` → pinned-regression workflow) |
| Lab / end-to-end | `lab/` (Vagrant/Hyper-V VMs) | real kernels: eBPF verifier behavior, SELinux, Windows ETW/eventlog, service installs — anything a unit test can't honestly claim |

## Platform reality

- `cargo test` on a macOS/Windows host runs everything cross-platform plus that
  host's gated code; the Linux sensors' gated tests need the Linux target or a
  lab VM. Clippy `--target x86_64-unknown-linux-gnu` compile-checks them from
  any host (the gauntlet does this); *executing* them cross-target is not
  possible — that is what the lab and (native) CI legs are for.
- Root-only behavior (chown hardening, proc-connector, audit socket) is
  test-gated to skip politely when unprivileged, and validated for real in the
  lab.

## Coverage

```bash
cargo llvm-cov --workspace --exclude sensor-linux-ebpf --summary-only
```

Not a gate, a flashlight: the 2026-09-22 run sat at ~85% lines and its gaps
located two real problems (the untested detection-sink wiring and transport's
never-exercised HTTP path — both since covered). Interpret low numbers by
asking what the missed lines *are*, not by chasing the percentage.
