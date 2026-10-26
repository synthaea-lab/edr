# ADR-0039: Windows binary self-update (ADR-0015's deferred Windows slice)

- **Status**: proposed
- **Date**: 2026-10-26

## Context

ADR-0015 scoped binary self-update to Linux only and named Windows explicitly in its
Deferred section: "no versioned-layout convention exists yet (the MSI installs flat
into `INSTALLFOLDER`); needs its own design, possibly MSI-driven re-install rather
than a symlink-style swap." Issue #71's remaining checklist still lists the
self-integrity monitor (`agent/src/integrity.rs`) as "Linux only — no call site in
`commands/windows.rs` or a macOS equivalent yet," and that module calls
`updater::layout::Layout`, whose entire module is `#[cfg(target_os = "linux")]`
(`crates/updater/src/lib.rs:33`) — it does not exist in a Windows build at all. Wiring
the monitor into Windows is gated on this layout existing there first.

What Windows actually has today, from `packaging/windows/` and `watchdog/src/service/windows.rs`:

- **The MSI installs flat.** `SynthaeaAgent.msi` drops `agent.exe`/`watchdog.exe`
  directly into `Program Files\Synthaea` (`packaging/windows/README.md`), no
  `bootstrap`/`current`/`versions` convention. Signing is explicitly "not yet
  decided" (same doc) — but that is Authenticode code-signing for SmartScreen/
  AppLocker trust of the PE files, a *different* concern from this ADR's manifest
  signature (ADR-0015 Decisions 2-4: a baked-in Ed25519 key verifying a hash
  manifest, same scheme Linux already uses with unsigned ELF binaries). This ADR
  does not need the Authenticode question resolved to proceed.
- **The watchdog self-registers as an SCM service running as `LocalSystem`**
  (`watchdog/src/service/windows.rs:136`'s doc: `SY` keeps full rights in the
  hardened ACE string). `cmd_install` (`:182`) persists the resolved watchdog and
  agent paths into the service's `binPath` as a literal command line
  (`build_bin_path`, `:266`): `"<watchdog.exe>" run --agent-bin "<agent.exe>"
  --alerts "<path>"`. Both paths are **canonicalized** before being persisted
  (`:202-208`) — deliberately: the `#103` hardening comment right above it
  (`:191-201`) flags that this project has not yet audited a DACL-based
  alternative to Unix's world-writable-directory check, so resolving through any
  redirection at install time, rather than trusting a path indirection to still
  point somewhere safe at every future launch, is the considered posture already
  in the code, not an oversight.
- **The service ACL is hardened after install** (`harden_service_acl`, `:163`,
  called at `:250`): the SDDL string denies `BA` (built-in Administrators)
  `SERVICE_CHANGE_CONFIG` (`DC`) along with `SERVICE_STOP`/`SERVICE_PAUSE_CONTINUE`/
  `DELETE` — only `SY` keeps it. `cmd_install` itself needs that right for its own
  `sc description`/`sc failure` calls, so it already calls
  `reset_service_acl_best_effort()` (`:178`, sets a permissive SDDL) first and
  `harden_service_acl()` last. Any future code that needs `SERVICE_CHANGE_CONFIG`
  on an already-hardened service — this ADR's `sc config binPath=` included — must
  follow the same reset-then-reharden bracket or it silently fails for anyone but
  `SYSTEM`.
- **`%ProgramData%\Synthaea\`, not `Program Files`, is already this codebase's
  convention for mutable state** — the `--alerts` test fixture at
  `watchdog/src/service/windows.rs:347` uses
  `C:\ProgramData\Synthaea\alerts.ndjson`. `Program Files\Synthaea` is
  admin-write-protected by default ACLs, matching the "package-owned, never
  touched by the updater" property Linux's `bootstrap/` has by virtue of package
  ownership (`packaging/linux`'s systemd unit never writes there either).
- **NTFS directory symlinks are available and transparently followed.** The
  service runs as `LocalSystem`, which holds every privilege including
  `SeCreateSymbolicLinkPrivilege` — unlike an unprivileged user, who needs
  Developer Mode enabled to create one. `std::fs::rename` on Windows maps to
  `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)`, which replaces a reparse point
  atomically the same way Linux's `rename(2)` replaces a symlink (ADR-0015
  Decision 5's guarantee). A running process keeps its own file mapped by handle,
  not by path — Windows allows renaming (not overwriting) a file a process has
  open from it, so swapping what a *directory* symlink points at while the old
  target's `watchdog.exe` is still the running image is safe, the same property
  Linux's design already relies on.
- **Linux's `ExecStart=` launches *through* the `current` symlink**
  (`packaging/linux`'s unit file:
  `ExecStart=/var/lib/synthaea/current/watchdog run --agent-bin
  /var/lib/synthaea/current/agent ...`), so systemd re-resolves `current` fresh on
  every `systemctl restart` — the unit file itself never changes across an
  update. Windows's `cmd_install` does the opposite on purpose (canonicalizes away
  any indirection before persisting `binPath`), so the direct Linux parallel — "flip
  the symlink, restart the service, the OS re-resolves the path" — does not apply
  as-is without either reversing that canonicalization (touching tested,
  deliberately-written install code) or having the updater rewrite `binPath`
  explicitly on every promote/rollback. This ADR takes the second path (Decision
  3) to leave `cmd_install`'s existing security posture alone.

This ADR scopes a second, Windows-only slice of ADR-0015's self-update mechanism,
reusing its manifest format, signature scheme, and rollback/health-check model
without change. It does not revisit any Linux decision.

## Decision

1. **Scope**: signed, staged, rollback-capable **binary** self-update
   (`agent.exe`/`watchdog.exe`) on **Windows only**, extending ADR-0015 rather than
   replacing any part of it. macOS binary self-update remains unimplemented and
   undesigned (ADR-0015 Deferred still applies there). Content distribution is out
   of scope here exactly as it was in ADR-0015.

2. **Manifest shape and signature: unchanged, reused as-is.** The same
   `ReleaseManifest` envelope (`schema_version`, monotone `release_version`,
   `entries: BTreeMap<PathBuf, String>`, Ed25519 signature via `ring`) that
   ADR-0015 Decision 2 defined. One difference: `entries`' paths are
   backslash-insensitive on read (normalize to forward slashes before lookup,
   same normalization `tools/check-deps.py`-adjacent code already does elsewhere
   in this workspace) so a manifest built on either platform's path separator
   convention verifies the same way; the manifest itself still stores
   forward-slash strings per ADR-0015 Decision 2, now cross-platform rather than
   "POSIX-native already" by coincidence.

3. **Layout**: `updater::layout` grows a Windows-native sibling, not a
   `cfg`-abstracted trait with two bodies — the two platforms' primitives
   (symlink + `rename(2)` vs. `CreateSymbolicLinkW` + `MoveFileExW`, plus the
   `sc config` step Decision 4 below adds) differ enough that one shared
   abstraction would hide more than it clarifies, matching this crate's existing
   `#[cfg(target_os = "linux")]`-gated-module convention (ADR-0015 Consequences)
   rather than inventing a cross-platform API surface that would misleadingly
   suggest parity.
   - **Base directory**: `%ProgramData%\Synthaea\` (already this codebase's
     convention for mutable state; see Context).
   - **Bootstrap-equivalent**: `Program Files\Synthaea\` itself — the MSI's own
     install directory, admin-write-protected by default NTFS ACLs, exactly the
     "package-owned, never touched by the updater" property Linux's `bootstrap/`
     has. No separate copy is made; day 0 (nothing ever promoted) runs directly
     from here, the same "day 0 trust is the installer's job" posture as ADR-0015
     Decision 7.
   - **`versions\vN\`**, under the `%ProgramData%\Synthaea\` base: staged,
     verified, promoted releases — directly analogous to Linux's `versions/`.
   - **`current`**: an NTFS directory symlink under the base directory, pointed
     either at a `versions\vN\` directory or absent (meaning "day 0, running from
     `Program Files\Synthaea`" — the Windows reading of ADR-0015 Decision 7, since
     there is no single `bootstrap`-named directory to point at across the
     `Program Files`/`ProgramData` split). Kept for the same reason
     `resolve_active_dir()` exists on Linux: a single place for the self-integrity
     monitor, `apply-release`, and an operator to ask "what's active" without
     parsing `binPath`. **Not** what the SCM launches through (Decision 4) —
     Windows is not re-deriving Linux's "launch through the symlink" trick, per
     the canonicalization finding in Context.

4. **Promotion mechanics**: `apply-release` (the same one-shot, operator/timer/
   scheduler-invoked command ADR-0015's amendment describes, extended to dispatch
   on `cfg(windows)`) does, after staging and verifying `versions\vN\` the same
   way as Linux (Decision 2's shared manifest/verification code path):
   1. Flips the `current` symlink to `versions\vN\` (`MoveFileExW`-backed rename
      of a freshly built symlink over the old one, same atomicity as ADR-0015
      Decision 5 — bookkeeping only, see Decision 3).
   2. Calls `reset_service_acl_best_effort()` (reusing
      `watchdog/src/service/windows.rs`'s existing function — `updater` and
      `watchdog` are both leaves `agent`/`cli` already depend on, so `updater`
      taking a dependency on `watchdog`'s service module, or that function moving
      to a shared location, is an implementation detail this ADR does not pin
      down), then `sc config SynthaEDR binPath= "<versions\vN\watchdog.exe
      resolved> run --agent-bin <versions\vN\agent.exe resolved> --alerts
      <alerts path>"` — same `build_bin_path` format, same canonicalize-before-
      persist posture `cmd_install` already uses, just computed against the new
      version's resolved paths instead of the MSI's. Then
      `harden_service_acl()` again, mirroring `cmd_install`'s existing
      reset-then-reharden bracket exactly (Context) — skipping this step means an
      admin-run `apply-release` silently fails to retarget the service with no
      visible error beyond an access-denied from `sc config`, which must surface
      as a **hard failure** (Decision 5's `Failed` outcome), not a logged warning,
      since a successfully-staged-but-not-promoted release is safe (`current`
      still resolves the old way) but a promoted-on-disk, not-promoted-in-`binPath`
      state is a silent lie about what's running.
   3. Restarts the service (`sc stop` then `sc start`, or `ControlService` plus
      the existing `sc failure` auto-restart — either is fine, this ADR does not
      pin the exact restart primitive down) so the new `binPath` takes effect; the
      currently-running old-version watchdog process keeps running from its own
      open file handle until this restart actually happens (Context), so there is
      no window where the service is simultaneously "promoted" and "running
      neither version."

5. **Rollback and health check: same model as ADR-0015 Decision 6/the
   watchdog-probation amendment, Windows primitives substituted.** A watchdog
   started from `versions\vN\` (its own `current_exe()` path says so, mirroring
   the Linux check) is on probation unless `versions\vN\.healthy` exists, proven
   by the same progress-backed heartbeat file (#102) advancing within 120s
   (`NO_CANARY_SILENCE_DEADLINE_NS`, unchanged). On failure, the watchdog
   performs the same `sc config`-bracketed-by-ACL-reset/reharden rewrite back to
   the previous known-good target (the newest `versions\vN\` with `.healthy` set
   and not banned, or `Program Files\Synthaea` with none — `Layout::rollback_target`'s
   logic, ported as-is since it is pure path/metadata reasoning with nothing
   Linux-specific in it), bans the failed `release_version` in the same
   `banned_versions.json` shape and location convention
   (`%ProgramData%\Synthaea\banned_versions.json`), flips `current` back, and
   exits non-zero so `sc failure`'s configured restart action (already set by
   `cmd_install`, Context) relaunches from the rolled-back `binPath`. On success,
   the watchdog writes `.healthy` and prunes releases older than the rollback
   target, same as Linux (ADR-0015 Decision 8/amendment).

6. **Failure recovery — a real gap this ADR does not close.** Linux's safety net
   for "the thing `ExecStart` points at cannot even exec" is
   `ExecStartPre=.../bootstrap/watchdog recover`, always run by systemd before
   every service start attempt, including every automatic restart. Windows's SCM
   has no equivalent hook: `sc failure`'s configured action restarts the *same*
   `binPath`, so if a promoted `versions\vN\watchdog.exe` is missing or cannot
   start, the service crash-loops on a `binPath` that will never succeed, with no
   automatic path back to `Program Files\Synthaea`. This is not a case Decision 5
   introduces by itself (normal promotion/rollback never points `binPath` at a
   directory `prune` has removed — `prune` only ever removes a release strictly
   older than the current rollback target), but it is a real, lower floor than
   Linux's for anything else that corrupts the pointed-at release out of band.
   **Deferred, not solved here**: a `watchdog.exe recover` one-shot subcommand
   that resets `binPath` to `Program Files\Synthaea` exists in design only; wiring
   it to actually run automatically (a Scheduled Task watching the service's
   failure count, or accepting that this is an operator-invoked break-glass tool
   like `cmd_uninstall` already is) is an open question for whoever implements
   this slice, not answered by this ADR.

## Consequences

- `updater::layout` gains a Windows module (`#[cfg(target_os = "windows")]`),
  parallel to, not sharing a trait with, the Linux one — new code, not a
  refactor of the existing Linux path.
- `agent/src/integrity.rs` (issue #71) can finally gain a Windows call site once
  this layout exists: `commands/windows.rs` wires `integrity::spawn_monitor` the
  same way `commands/linux.rs:391` already does, closing that half of #71's
  remaining Windows gap. The other named gap — `agent::protected`'s Windows
  wiring — is unaffected by this ADR; it depends on the eventlog/ETW event
  stream already existing on Windows (it does) and the updater-allowlist problem
  ADR-0015 Consequences already deferred to #71, which this ADR does not change:
  an `apply-release` promotion on Windows stages into a fresh `versions\vN\`
  before touching `binPath`, the same non-overlapping-write property that let
  ADR-0015 settle this for Linux without an allowlist.
- `watchdog/src/service/windows.rs` gains no new public surface for this ADR
  beyond what `updater`/`apply-release` needs to call
  (`reset_service_acl_best_effort`/`harden_service_acl`, or a moved equivalent) —
  `cmd_install`'s own behavior is unchanged.
- First cross-platform exercise of the ADR-0015 manifest format: the path-separator
  normalization in Decision 2 is a small, real change to code Linux also uses,
  and needs a fixture proving a manifest built on one platform's separator
  convention verifies on the other.
- Signing/Authenticode (packaging/windows/README.md's "not yet decided") remains
  exactly as unresolved as before — this ADR does not depend on it and does not
  resolve it.

## Deferred

- **The `watchdog.exe recover` fallback and what triggers it** (Decision 6) —
  real design work, not a gap this slice closes.
- **macOS binary self-update** — no packaging exists yet at all; ADR-0015's
  Deferred entry for it is unchanged.
- **Moving `reset_service_acl_best_effort`/`harden_service_acl` to a location
  both `watchdog` and `updater` can call** — an implementation detail, not pinned
  down here (Decision 4).
- **Authenticode code-signing for `agent.exe`/`watchdog.exe`/the MSI** —
  unrelated to this ADR's manifest-signature mechanism; tracked separately on
  #37.
- **Production key generation, storage, and rotation, and the compromised-key
  revocation path** — identical open question to ADR-0015 Deferred; this ADR
  adds no new key material (Decision 2 reuses the same embedded Ed25519 public
  key).

## References

- ADR-0015 — Updater: staged self-update, manifest signing, and rollback
  (Linux-first slice) — this ADR's Windows counterpart; every decision not
  restated here is unchanged from it.
- Issue #30 — "Build updater: self-update + content distribution client."
- Issue #71 — "Build tamper: runtime self-protection" — the self-integrity
  monitor's remaining Windows gap this ADR unblocks.
- Issue #37 — "Packaging: Windows (MSI + services)" — the flat-install layout
  this ADR extends; the signing question it leaves open and this ADR does not
  depend on.
- `watchdog/src/service/windows.rs` — `cmd_install`, `build_bin_path`, the
  hardened/permissive service ACL strings — the existing Windows service
  mechanics this ADR's promotion/rollback steps reuse rather than duplicate.
- `crates/updater/src/layout.rs` — the Linux `Layout` this ADR's Windows module
  parallels (not shares a trait with).
- `packaging/windows/README.md` — the MSI's current flat-install behavior and
  its open signing question.
