# ADR-0015: Updater — staged self-update, manifest signing, and rollback (Linux-first slice)

- **Status**: accepted
- **Date**: 2026-09-21

## Context

`crates/updater` is an empty stub (no dependencies, module doc only). Issue #30
asks for "staged, signature-verified self-update with rollback" plus "rule/model
download via canary rings" — two different problems wearing one issue number.

Two other ADRs already assume the updater exists and defer hard questions to it:

- ADR-0010 (shared policy model) names Ed25519 as the policy-signing scheme and
  explicitly defers "distribution mechanism — canary rings via the M6 updater"
  and "rollback of a failed policy application ... the M6 updater needs an atomic
  rollback path and a way to prevent the same broken version from being
  reapplied" — the exact rollback problem a binary self-update also has.
- ADR-0002 (ML model delivery) states "the `updater` trust chain must cover [a
  model] before the first canary ring" as a hard prerequisite.

`crates/tamper::integrity::Manifest` already hashes-and-compares
`(path, sha256)` pairs against the live filesystem, and its own doc says
"the manifest is the root of trust: its authenticity is the updater's job
(signed distribution, ADR-0001)" — a stale citation; ADR-0001 is the server
stack and has no signing content. There is no ADR that actually specifies the
updater's manifest format or signing scheme. `docs/architecture/threat-model.md`
names issue #30 directly: "the manifest chain (updater #30) is the root of
trust" for detecting a swapped binary.

No signing crate exists in the workspace despite ADR-0010's Ed25519 choice —
`ed25519-dalek` has zero hits anywhere, including `Cargo.lock` transitively.
`ring` (0.17.14) is already present transitively (via `ureq`'s TLS stack in
`crates/transport`) and supports Ed25519 (`ring::signature`) — a reuse
candidate that avoids introducing a new top-level dependency for the first
implementation.

Platform reality is uneven. Linux packaging (issue #36) already ships a
concrete layout the updater is meant to manage: package-owned
`bootstrap/{agent,watchdog,cli}` (never touched by the updater) plus a
`current -> bootstrap` symlink and an empty `versions/` directory tree meant
for updater-managed version swaps. Windows packaging (issue #37) has no
equivalent — the MSI drops binaries directly into `INSTALLFOLDER`, no
versioned layout, and code-signing is explicitly "not yet decided." macOS
packaging doesn't exist yet at all.

Issue #30 as written is too large for one implementation pass across three
platforms plus a network content-distribution system. This ADR scopes a first,
concrete slice: **binary self-update on Linux only**, using the existing
packaging layout and `tamper::Manifest` shape. Canary-ring *content*
distribution (rules, models — issues #73, #49) and Windows/macOS binary
self-update are named and deferred, not designed here.

## Decision

1. **Scope**: this ADR covers signed, staged, rollback-capable **binary**
   self-update (agent/watchdog/cli) on **Linux only**. Content distribution
   (rule/model updates via canary rings, per-ring telemetry, auto-halt) and
   Windows/macOS binary self-update are explicitly out of scope — see
   Deferred.

2. **Manifest shape**: reuse `tamper::integrity::Manifest`'s `(PathBuf, sha256
   hex)` entries as the payload, wrapped in a versioned, signed envelope
   following ADR-0010's document shape:
   - `schema_version: u32` — readers reject an unknown value.
   - `release_version: u64` — monotone, strictly increasing; a downloaded
     manifest with a `release_version` not greater than the currently
     installed one is rejected outright (anti-rollback-attack, same
     reasoning as ADR-0010's `policy_version`).
   - `entries: BTreeMap<PathBuf, String>` — path (relative to the version
     directory) → expected sha256 hex, same field this ADR's payload borrows
     from `tamper::integrity::Manifest`. Serialized as forward-slash strings
     (the scope is Linux-only, so paths are POSIX-native already — no
     separator translation needed, unlike a cross-platform manifest would).
   - `signature` — Ed25519 over the canonical JSON serialization (indent=2,
     sorted keys, `signature` field set to `""` before signing — the empty
     string, not omitted or null, so the field's presence in the schema is
     fixed and only its content varies) — identical canonicalization rule to
     ADR-0010/ADR-0009, so there is exactly one canonicalizer in the
     workspace, not a second one for updater manifests. ADR-0010 specifies
     the same "fixed placeholder" mechanism without pinning its exact value;
     this ADR's `""` is the first concrete instance and the value ADR-0010's
     own implementation should match when it lands, for one convention
     instead of two.

3. **Signature verification via `ring`**, not `ed25519-dalek`. Same algorithm
   ADR-0010 named; different crate, because `ring` is already a transitive
   dependency and `ed25519-dalek` would be a new one for the same
   capability. This is an implementation substitution, not a scheme change —
   ADR-0010's choice of *Ed25519* stands.

4. **Key material**: the Ed25519 **public** key is a compile-time constant
   baked into the `updater` crate (`const UPDATER_PUBLIC_KEY: [u8; 32]`),
   the same "no round-trip to a KMS in-band" reasoning ADR-0010 already
   applied to policy verification. This means rotating the key requires
   shipping a new binary — acceptable because the updater's own binary is
   itself subject to this ADR's update mechanism, so key rotation is just
   another signed release (see Deferred for the one bootstrap case this
   doesn't cover: rotating *away from* a compromised key).
   Ships with a **test-only keypair** and an explicit
   `SYNTHAEA_UPDATER_TEST_KEY` (or equivalent) marker distinguishing it from a
   production key, mirroring ADR-0010's `SYNTHAEA_STRICT_PROVENANCE`-style
   dev/prod split. Real key *generation* and *custody* (where the private key
   lives, who can invoke a signing) are deferred (see Deferred) — this ADR
   fixes the verification mechanism and where the public half lives, not
   private-key custody.

5. **Layout and atomic swap**: extends the existing Linux packaging
   convention (`packaging/linux/README.md`) rather than inventing a new one.
   `updater`:
   - downloads/stages a new release under `versions/vX.Y.Z/` (never touches
     `bootstrap/`),
   - verifies the manifest signature, then every listed file's sha256 against
     what was staged,
   - on success, atomically repoints the `current` symlink at the new
     `versions/vX.Y.Z/` directory (`rename(2)` on the symlink, not an in-place
     edit — a crash mid-swap leaves either the old or the new target, never a
     half-written one),
   - triggers a controlled restart of the watchdog-supervised agent/watchdog
     process against the new `current` target.

6. **Rollback**: the previous `versions/` directory is kept (not deleted) until
   the new release passes a health check. Health check reuses
   `tamper::heartbeat::SilenceMonitor` machinery already in the agent: the
   updater registers the freshly restarted process's primary heartbeat the
   same way `agent/src/commands/linux.rs` already registers every other
   no-canary sensor — one `register()` call at process start, bound by the
   existing `NO_CANARY_SILENCE_DEADLINE_NS` (120s), not a new number invented
   for this ADR. `register()`'s own semantics ("a sensor that never pulses is
   caught one deadline after registration, not never") already answer the
   "what if it's slow, not dead" question: the clock starts at registration
   (process start), so a slow-but-alive process has the same 120s every other
   sensor gets before being called silent, no new race to reason about. If
   the heartbeat doesn't advance within that window, the updater flips
   `current` back to the previous version directory and marks the failed
   `release_version` as banned — a banned version is refused even if offered
   again (closes the exact gap ADR-0010 flagged: "a way to prevent the same
   broken version from being reapplied"). The ban list is a small local file,
   `/var/lib/synthaea/banned_versions.json` (a bare `[release_version, ...]`
   array — no signature needed, since it only ever narrows what this specific
   install will accept, the same trust boundary as the install itself), read
   at `updater` startup and appended to on each rollback. No admin override in
   this slice — un-banning means deleting the entry by hand, same operational
   tier as any other file under `/var/lib/synthaea` today.

7. **Bootstrap — the first trusted state**: this ADR's signature chain covers
   the *update* path (`bootstrap` → `versions/vX`) only; it does not need to
   verify the package-installed `bootstrap/` binaries themselves. Day-0 trust
   is the OS package manager's job (`.deb`/`.rpm` — package signing is
   already tracked as future work on issue #36), not the updater's — `current`
   starts pointed at `bootstrap` (per the existing packaging layout) and the
   updater's manifest signature only has to prove itself from the first
   *update* onward. No chicken-and-egg: the updater never has to bless its
   own starting point.

8. **Disk space**: exactly two release trees coexist under `versions/` —
   `current`'s target and the one it would roll back to. Once a new release
   passes its health check (Decision 6), the updater deletes the
   now-superseded older version, keeping the count at two steady-state. A
   release that's mid-rollback-window keeps both until the outcome is known.
   No preflight free-space check in this slice (that needs real disk-usage
   probing, a separate concern from signing/rollback) — a staging download
   that fails partway for lack of space fails the same way any other
   incomplete download does (manifest verification rejects a short/corrupt
   stage before anything is swapped in), so the failure mode is safe, just
   not preemptively diagnosed. Preflight space checks are deferred, not
   silently skipped.

9. **Failure recovery — corrupted `current`**: `current` is only ever changed
   by a `rename(2)` symlink swap (Decision 5), so a torn write is not
   possible — the symlink either still points at the pre-swap target or the
   post-swap one. The one failure this doesn't cover is external corruption
   (`current` deleted or pointed somewhere outside `versions/`/`bootstrap`
   entirely, e.g. manual tampering or a bug elsewhere). On startup, if
   `readlink(current)` fails or resolves outside the expected set, the
   watchdog falls back to `bootstrap/` — the one path guaranteed to exist,
   package-owned and never touched by the updater — rather than refusing to
   start.

### Amendment: the update trigger and its wire contract (issue #30)

Nothing in this ADR said what starts an update. `agent apply-release` does, and
it is deliberately a one-shot command (run by an operator, a timer or a future
scheduler), not a resident loop:

1. `GET /api/release/manifest` returns the signed `ReleaseManifest` this agent is
   offered. There is **no ring in the path**: unlike content, a binary release
   manifest has no `ring` field, and which release an agent is offered is the
   server's decision from its mTLS identity. The Ed25519 signature and the
   monotone `release_version` are what the agent relies on.
2. Before any download the agent verifies the signature and schema, rejects any
   entry path that could escape the release directory, refuses a banned release,
   and applies the anti-rollback check against `current`'s version.
3. Each artifact is fetched with `GET /api/release/artifact?release_version=N&path=P&sha256=H`,
   hash-checked against the signed manifest **before it touches disk**, and
   written (mode `0755`, symlink-safe, atomically) into `versions/.stage-N`. The
   manifest has no signed per-entry size, so a constant ceiling
   (`MAX_RELEASE_ARTIFACT_BYTES`, 256 MiB) bounds each download instead.
4. The staging directory is renamed to `versions/vN` in one step, so a release
   directory only ever exists complete and a crash mid-download can never leave a
   half-populated directory that a later rollback might pick as its target.
   `verify_staged` then re-hashes the tree from disk, the manifest is persisted,
   and only then is `current` repointed. A complete `vN` from an interrupted run
   is reused without downloading; one that no longer matches its manifest is
   refused and left in place for inspection.
5. The command then runs `systemctl restart synthaea-agent`, which starts the
   watchdog from the new `current`; a failed restart is a warning, not an error,
   since a promoted release is safe and simply runs at the next service start.
   `--no-restart` skips it.

Both the manifest and artifact routes are the contract a server must implement;
the server side is a separate slice. Windows and macOS remain out of scope: the
command exits with an explanatory error there.

### Amendment: how the Decision 6 health gate is implemented (issue #30)

Decision 6 said the updater registers the new process with `SilenceMonitor`. The
implementation differs in two ways, both because the *watchdog* is the one process
that outlives the agent and can act on a failure:

- **The watchdog runs the probation, not the updater.** A watchdog started from
  `versions/vN/` (its own executable's path says so; `bootstrap/` and development
  binaries never qualify) puts `vN` on probation unless `versions/vN/.healthy`
  exists. The proof of life is the progress-backed heartbeat file (#102) advancing
  at least once within 120s of the watchdog starting: the same deadline as
  `NO_CANARY_SILENCE_DEADLINE_NS`, and the same signal the watchdog already polls,
  rather than a second liveness mechanism. The clock covers agent crashes and
  refused spawns too, so a release whose agent never starts still runs out its
  probation.
- **Failure ends the watchdog process.** After `updater::rollback` (repoint
  `current` at the previous release, or `bootstrap` for the first release; ban the
  failed one) the watchdog exits non-zero and the service manager restarts it from
  the rolled-back `current`. Nothing re-execs in place.

On success the watchdog writes `.healthy` into the release directory and deletes
every release older than the one it would roll back to (Decision 8).

The rollback target is the newest older release that is **known good**: it has its
own `.healthy` marker and is not on the ban list. With none, the target is
`bootstrap`. A release that never proved itself, or that failed, is never a target,
and rolling back also deletes the failed release's directory (the ban list keeps
`apply-release` from re-staging it), so two bad releases in a row both land on the
last proven one and a later good release cannot prune it away.

Guards: rollback is skipped when `current` no longer points at the watchdog's own
release (a stale watchdog must not undo a newer promotion), and a rollback that
itself fails is reported and leaves the release running rather than crash-looping.

Not covered (still open under #30): a release whose *watchdog* binary fails to
start never reaches this code, so the service manager just restarts it; that case
needs the Decision 9 fallback at the unit level.

## Consequences

- `tamper::integrity::Manifest` gains no new fields or API — the updater's
  signed envelope is a wrapper around the same `(path, sha256)` shape, built
  once verification succeeds, then handed to the existing `Manifest::verify()`
  for the ongoing runtime integrity check `tamper` already does. The stale
  `integrity.rs` comment citing ADR-0001 is corrected to cite this ADR.

- First real cryptographic-signing dependency in the workspace (`ring`'s
  `signature` module). No new top-level crate added.

- Two new on-disk artifacts under `/var/lib/synthaea/`, alongside the
  existing `bootstrap`/`current`/`versions` layout: `updater`'s embedded
  public key (compiled into the binary, not a file) and
  `banned_versions.json` (Decision 6). `packaging/linux/README.md`'s
  directory listing should gain `banned_versions.json` when this ADR is
  implemented — not done here, since the file doesn't exist until the code
  does.

- `updater` becomes the one process authorized to write `versions/` and flip
  `current` — `docs/architecture/threat-model.md`'s "only `updater` may
  change [installed artifacts]" line gets an actual mechanism behind it.
  `agent::protected` (issue #71's protected-resource monitor) still has no
  concept of "this write came from the legitimate updater" (that gap is
  pre-existing, tracked on #71, unaffected by this ADR) — until it does, an
  update in progress will trigger protected-resource alerts on its own writes;
  acceptable for this slice, flagged for whoever wires that allowlist next.

- Windows and macOS binary self-update remain unimplemented after this ADR.
  `updater`'s Linux-specific pieces are `cfg(target_os = "linux")`-gated,
  matching the sensor-crate convention (empty stub elsewhere) rather than a
  cross-platform no-op API surface that would misleadingly suggest parity.

- Canary-ring *content* distribution (rules, models) is unaffected by this
  ADR and remains fully open — #73 and #49 still need their own design for
  ring membership, per-ring telemetry, and auto-halt. This ADR's
  `release_version`/rollback mechanism is written so a future content-update
  ADR can reuse it rather than invent a second one, but that reuse is not
  designed here.

## Deferred

- **Production key generation, storage, and rotation** — ships test-only for
  this slice, same posture ADR-0010 took for policy signing. Needs its own
  decision once there's a real control-plane release process to sign against.
  Until then `agent apply-release` **refuses to run** while
  `SYNTHAEA_UPDATER_TEST_KEY` is set unless given `--allow-test-key`: the test
  seed is public, so a valid signature proves nothing about who produced a
  release, and the command installs and restarts onto it as root. The flag is for
  lab and development hosts; the guard disappears with the constant once a
  production key is embedded, and no scheduler or operator documentation should
  invoke the command before that.
  Routine rotation is covered by Decision 4 (the key is just another signed
  release), but rotating *away from a compromised key* is not: a compromised
  key can sign a "rotate to this new key" release too, so that case needs an
  out-of-band revocation path (e.g. a second, offline-held key, or a hardcoded
  ban list shipped via the package rather than the updater channel) — real
  design work, not a gap this slice can close.
- **Preflight disk-space checks before staging a download** — Decision 8
  leaves this unimplemented; failure is safe (rejected at manifest
  verification) but not diagnosed ahead of time.
- **Canary-ring content distribution mechanics** (rule/model updates,
  per-ring telemetry, auto-halt on regression) — issues #73/#49, a separate
  ADR when that work starts.
- **Windows binary self-update** — no versioned-layout convention exists yet
  (the MSI installs flat into `INSTALLFOLDER`); needs its own design,
  possibly MSI-driven re-install rather than a symlink-style swap.
- **macOS binary self-update** — no packaging exists yet at all.
- **`agent::protected`'s updater allowlist** — recognizing the updater as a
  legitimate writer to avoid self-triggered protected-resource alerts during
  an update; tracked on #71.
- **Download transport security beyond TLS** — this ADR assumes fetching over
  the same mTLS-terminated channel the rest of the fleet uses
  (`threat-model.md` line 30); no additional transport hardening designed here.

## References

- Issue #30 — "Build updater: self-update + content distribution client"
  (this ADR's issue; scopes down to the binary-self-update half).
- Issue #73 — "Detection-as-code ... ring deployment" (shares the canary-ring
  mechanism, deferred here).
- Issue #49 — "Per-site model adaptation loop" (explicitly depends on
  "#30 (updater rings)").
- ADR-0010 — Shared policy model (canonical JSON, `schema_version`/monotone
  version pattern, Ed25519 choice this ADR's signature scheme follows).
- ADR-0009 — Model record / scenario-replay binding (the canonical JSON
  precedent ADR-0010 and this ADR both reuse).
- ADR-0002 — ML model delivery and inference (names the updater trust chain
  as a hard prerequisite for shipping models).
- `crates/tamper/src/integrity.rs` — the `Manifest`/`verify()` API this ADR's
  envelope wraps.
- `docs/architecture/threat-model.md` — names issue #30 as the intended root
  of trust for the installed-artifact integrity chain.
- `packaging/README.md`, `packaging/linux/README.md` — the
  bootstrap/current/versions layout this ADR extends rather than replaces.
