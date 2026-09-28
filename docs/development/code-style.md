# Code style: Clean Code principles and Rust practice

The bar this codebase holds itself to, and how each rule is enforced. Everything here
is either checked by CI (workspace lints in the root `Cargo.toml`, clippy with
`-D warnings` on three OSes, `cargo fmt`, `tools/check-deps.py`) or reviewed against
explicitly. If a rule matters and nothing enforces it, the fix is to add enforcement,
not to hope.

## Naming

- Names say **what** something is or does, in domain vocabulary (`SlidingCounter`,
  `is_trusted_system_path`, `drain_oldest`) — never mechanism trivia or abbreviations
  a newcomer must decode.
- One concept, one word, everywhere: an alert is an `Alert`, a detection a
  `Detection`, an event an `Event`; do not alternate between synonyms.
- Booleans and predicates read as questions (`is_duplicate`, `has_write_intent`,
  `needs_tail_repair`).
- Kernel/OS nomenclature wins over lint aesthetics where it is the clearer name:
  `pid`/`ppid`, `comm`, `daddr`/`dport` are the domain's words (this is why
  `clippy::similar_names` is deliberately not enabled).

## Functions

- Small, one level of abstraction per function. A dispatcher dispatches
  (`DetectionSink::on_event` routes to `detect_exec` / `detect_file_open` /
  `detect_connect`); the routed-to function does the work.
- No boolean flag parameters that change what a function means — write two functions.
- Command/query separation: a function either computes an answer or mutates state;
  the exceptions (like `SlidingCounter::record`, which prunes and counts) say so in
  their doc comment.
- Zero function-length or cognitive-complexity clippy findings is the observed state
  of the codebase; keep it that way by extracting, not by suppressing.

## Comments and documentation

- A comment states what the code **cannot** say: an invariant, a calibration
  decision, a lesson from a real incident (dates and scenario names welcome —
  "NjRAT FP 2026-08-28" is worth more than a paragraph of theory). Never what the
  next line does.
- Every `pub` item has a doc comment. Functions returning `Result` document
  `# Errors`; functions that can panic document `# Panics` (both enforced:
  `missing_errors_doc`, `missing_panics_doc`).
- Identifiers in prose are backticked (`doc_markdown` enforces it).
- Every `unsafe` block carries a `// SAFETY:` comment stating why its invariants
  hold (`undocumented_unsafe_blocks = deny`).
- Historical provenance comments (`old/...` paths) are allowed; commented-out code
  is not — delete it, git remembers.

## Errors

- Library crates define typed errors with `thiserror`; only binaries use `anyhow`.
- No `unwrap`/`expect` outside tests and provably-infallible cases — and a
  provably-infallible `expect` states its proof in the message or a `# Panics` doc.
- Failure handling is a design decision, stated where it happens: enrichment
  *degrades* (a field goes missing, the event survives), the spool *sheds oldest
  and counts the loss*, content loading *fails loudly* (broken shipped rules are a
  bug, not a warning). Pick the stance deliberately and write it down.
- Never log event payload contents at info level (`tracing`, structured fields).

## Boundaries and dependencies

- `schema` is the platform boundary and is semi-frozen; `policy` sits beside it.
  Sensor crates depend only on `schema` (+ their wire crate); detection crates never
  depend on a sensor; leaf crates depend only on the base tier. Enforced by
  `tools/check-deps.py` in CI — a new crate is classified in the same change.
- Platform-specific code lives **only** in `crates/sensors/*`, target-gated.
- `pub(crate)` by default. A crate's `pub` surface is its contract: minimal,
  deliberate, documented. `#[must_use]` on value-returning methods
  (`must_use_candidate` enforces it).

## State and resources

- Detection state on a long-lived agent is **bounded and observable**: LRU maps
  (`store::BoundedMap`) with eviction counters, bounded queues that shed and count
  (`yara::ScanQueue`, `store::EventSpool`). An unbounded `HashMap` keyed by
  attacker-influencable input is a memory-DoS bug.
- Reads from the filesystem on the event path are budgeted (`MAX_HASH_BYTES`,
  `MAX_SCAN_BYTES`), bounded (`Read::take`), and guarded (`is_file()` before open —
  a FIFO blocks forever).
- Windows of time are true sliding windows (timestamp deques), not reset buckets —
  reset buckets drop in-window events at the boundary.

## Detection-specific honesty

- Exclusions and allowlists document **why** each entry exists, with the date and
  scenario that produced the false positive.
- A name-keyed exclusion is a bypass unless gated on evidence (image path in a
  trusted location today — `policy::is_trusted_system_path`; signature and expected
  parent as the durable fix, issue #107).
- Attribution never fabricates: when identity resolution fails, the value is
  `User::Unknown` / `None`, not a plausible guess (the agent's own token is exactly
  wrong for the processes it could not open).

## Tests

- Every bug fix lands with the regression test that would have caught it, named
  after the behavior (`self_spawn_window_slides_instead_of_resetting`,
  `torn_tail_is_repaired_on_reopen`) and commented with the finding it pins.
- Golden fixtures are the parity mechanism (schema serialization, ML features):
  fixtures are superseded, never edited.
- Tests go through the public API; reaching into internals is a smell that the
  contract is missing something.
- Float comparisons in tests use an explicit epsilon, never `==`.
- Event literals in tests come from `schema::fixtures` (feature `test-fixtures`)
  via struct-update syntax — the baselines are deliberately neutral (zeros, empty,
  `Unknown`, TEST-NET-1 addresses) so a test asserting on a field it didn't set is
  visibly asserting on nothing. A new schema field is then one edit, not twelve.
  The golden suite spells every field on purpose and is the one exception.
- Byte parsers carry a **never-panic robustness suite** (deterministic seeded
  corpus, truncations, length-lying inputs — see
  `crates/sensors/linux/audit/tests/robustness.rs` for the shape) and, for the
  kernel-socket decoders, a coverage-guided fuzz target in `fuzz/` (its README
  documents the crash → `tmin` → pinned-regression-test workflow).

## File and module layout

- One responsibility per file. When a file accumulates a second concern, split it —
  the pattern used across the codebase:
  - `sigma`: `engine.rs` (loading) / `validate.rs` (load-time rejection) /
    `eval.rs` (matching) / `tests.rs`
  - `watchdog`: `paths.rs` / `supervise.rs` / `service/{windows,linux,macos}.rs` —
    one submodule per platform mechanism, each exporting the same
    `cmd_install`/`cmd_uninstall` pair
  - `ml::forest`: `mod.rs` (the model + attribution walk) / `onnx.rs` (protobuf
    extraction), split at the parse/consume seam
  - `rules`: `state.rs` (the rules) / `sliding.rs` (the counter) /
    `exclusions.rs` (calibration catalogues)
  - windows sensor: `sensor.rs` (lifecycle: session, liveness) / `providers.rs`
    (the three ETW callbacks) / `normalize.rs` / `winapi.rs`
- Layering in the web-dev sense maps onto Rust naturally, at two levels:
  **crates** are the coarse layers (the dependency-direction rules are exactly a
  layered architecture: `schema`/`policy` = domain contracts, sensors = adapters
  in, detection = services, `sinks`/`transport` = adapters out, binaries =
  composition roots that wire everything), and **modules** are the fine layers
  within a crate. There is no service-container/DI framework; the binary's `main`
  does the dependency injection by constructing engines and handing them to the
  sink — plain constructor injection, checked at compile time.
- Test placement: unit tests in a `#[cfg(test)] mod tests` (or `tests.rs` module)
  next to the code; cross-crate/content/golden suites in the crate's `tests/`
  directory; put a test in the file that owns the behavior it pins.

## Rust practice (the canon, applied here)

Distilled from the Rust API Guidelines, the Book, and Effective Rust — the subset
this project holds as rules:

**Ownership and types**
- Take `&str`/`&Path`/`&[T]` parameters, return owned types; take `self` by the
  least powerful mode that works (`&self` > `&mut self` > `self`).
- Make invalid states unrepresentable: enums over flag booleans
  (`Signature::{Valid,Invalid,Unsigned,Unsupported}`, `User::{Unix,Windows,Unknown}`
  — not `is_signed: bool` + `sid: Option<String>`).
- Newtypes and enums over primitive obsession where a value has rules; plain
  primitives where it doesn't (`pid: u32` is fine — the kernel's type).
- `#[non_exhaustive]` on public types that will grow (`schema::Event`).

**Traits**
- Prefer composition + traits over inheritance-style OOP. The codebase's OOP
  boundary is deliberate and small: `Sensor`/`EventSink` are trait objects
  (`dyn`) because sensors are true plugins chosen at runtime per platform;
  everything else is concrete types and generics. No trait hierarchies, no
  "base struct" emulation.
- Implement the standard traits where they're honest: `Debug` everywhere
  (redacting sensitive payloads), `Default` only when a no-argument value is
  meaningful, `Clone` only when cloning is cheap or clearly needed. Derive,
  don't hand-write, unless there's a reason (a reason worth a comment).
- Accept `impl Trait`/generics for flexibility in inputs; return concrete types.

**Error handling (beyond the thiserror/anyhow rule)**
- `?` all the way up; never `.ok()` away an error the caller should see.
- Error enums carry what the handler needs (the path, the rule name), not
  formatted prose; `#[error(...)]` renders the prose.
- Distinguish the three failure stances explicitly: degrade (enrichment),
  shed-and-count (queues, spool), fail loudly (content loading, model parsing —
  "model files come from the update channel; parsing must fail closed").

**Concurrency**
- Share state as `Arc<Mutex<_>>`/atomics behind a type that owns the policy
  (`ScanQueue`, `SharedState`) — never leak lock discipline to callers.
- Channels bounded (`sync_channel`), overflow counted. Threads named
  (`.name("yara-scan")`).
- `Ordering::SeqCst` for stop flags (correctness first); `Relaxed` only for
  counters where staleness is harmless.

**API hygiene**
- `#[must_use]` on value-returning methods; builders and constructors included.
- No `panic!` in library paths reachable from event data — panics are for
  violated internal invariants only, documented under `# Panics`.
- Iterators over index loops; `collect` into the right container directly;
  avoid needless `clone` (clippy's pedantic set patrols this).
- `matches!`, `let-else`, and early returns to keep the happy path unindented.

**Unsafe**
- Unsafe only at FFI boundaries, in `sensors/*` and `enrich::sig` — never in
  detection logic. Every block: `// SAFETY:` (enforced), smallest possible scope,
  checked return codes, handles closed on every path.

**Dependencies**
- Every new dependency is a decision: prefer std, then a small pinned crate;
  `cargo deny` gates licenses and advisories; wildcard/path deps only inside the
  workspace. `schema` stays dependency-light by contract.

## Enforcement summary

| Rule | Enforced by |
| --- | --- |
| Formatting | `cargo fmt` (CI) |
| Lint bar, all targets, 3 OSes | `cargo clippy -- -D warnings` (CI) |
| Curated lint set | `[workspace.lints]` in the root `Cargo.toml` |
| `dbg!`/`todo!`/`unimplemented!` never ship | `dbg_macro`, `todo`, `unimplemented` = deny |
| `// SAFETY:` on every unsafe block | `undocumented_unsafe_blocks` = deny |
| Docs: backticks, `# Errors`, `# Panics`, `#[must_use]` | `doc_markdown`, `missing_errors_doc`, `missing_panics_doc`, `must_use_candidate` |
| Dependency direction | `tools/check-deps.py` (CI) |
| The whole matrix, locally | `tools/gauntlet.sh` (pre-push convenience; CI is the enforcement — issue #318) |
| License/advisory hygiene | `cargo deny` (CI) |
| Shipped content compiles and fires | content suites (`sigma`, `yara` tests, CI) |

Cross-target note: local clippy only lints the code compiled for the host — a
macOS-only check misses every `cfg(windows)`/`cfg(linux)` item (it caught a real
Windows compile break, and doc-lint misses in Linux-only code). **`tools/gauntlet.sh`
runs the whole matrix below plus fmt/tests/deny/docs in one command** (and
`tools/hooks/pre-push` gates pushes on its fast slice — opt in with
`git config core.hooksPath tools/hooks`); the raw commands, for running a slice by
hand:

```bash
rustup target add x86_64-pc-windows-msvc x86_64-unknown-linux-gnu
# Linux needs a cross C toolchain for the wasmtime (yara-x) build:
brew install messense/macos-cross-toolchains/x86_64-unknown-linux-gnu

cargo clippy --workspace --exclude sensor-linux-ebpf --all-targets \
  --target x86_64-pc-windows-msvc -- -D warnings
CC_x86_64_unknown_linux_gnu=x86_64-unknown-linux-gnu-gcc \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-unknown-linux-gnu-gcc \
cargo clippy --workspace --exclude sensor-linux-ebpf --all-targets \
  --target x86_64-unknown-linux-gnu -- -D warnings
```
