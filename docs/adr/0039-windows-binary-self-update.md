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
   ADR-0015 Decision 2 defined. One difference: normalization happens once, at
   **build time**, in `release-tool` — never at verify time, and never
   per-platform. `release-tool` rejects a candidate entry outright (refuses to
   build the manifest, not a warning) if its path contains a `..` segment, a
   backslash (a legal filename character on Linux, so rewriting it to forward
   slash on read could make two different signed-over paths collide or resolve
   differently from what was actually signed — reviewed finding on this ADR),
   a colon anywhere but a Windows drive letter's second character (an
   alternate-data-stream name), a `\\?\`-prefixed or UNC form, or a component
   that is (case-insensitively, with or without an extension) one of the
   Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`,
   `LPT1`-`LPT9`). What survives is stored as a forward-slash string, exactly
   as ADR-0015 Decision 2 already did. On read, Windows's `Layout` looks entries
   up case-insensitively (NTFS's own default collation); Linux's keeps the
   existing case-sensitive lookup — both compare against the one canonical set
   of strings the manifest actually carries, so there is nothing left to
   normalize per platform at verify time.

3. **Layout**: `updater::layout` grows a Windows-native sibling, not a
   `cfg`-abstracted trait with two bodies — the two platforms' primitives
   (symlink + `rename(2)` vs. `CreateSymbolicLinkW` + `MoveFileExW`, plus the
   `sc config` step Decision 4 below adds) differ enough that one shared
   abstraction would hide more than it clarifies, matching this crate's existing
   `#[cfg(target_os = "linux")]`-gated-module convention (ADR-0015 Consequences)
   rather than inventing a cross-platform API surface that would misleadingly
   suggest parity.
   - **Base directory**: `%ProgramData%\Synthaea\` (already this codebase's
     convention for mutable state; see Context) — created, the first time
     anything under it is written (MSI install or `apply-release`'s first run,
     whichever happens first) with an explicit DACL granting write access only
     to `SYSTEM` and `BUILTIN\Administrators`, not inherited from
     `%ProgramData%`'s own default ACL (which grants `BUILTIN\Users`
     create-subfolder rights on a stock install). This is **required**, not
     best-effort: the service runs the binaries under it as `LocalSystem`
     (Context), so a writable-by-everyone `versions\vN\` is the same
     plant-then-`sc config`-runs-it-as-SYSTEM path the Linux design's
     world-writable-directory check exists to close, and the `#103` comment
     already in `watchdog/src/service/windows.rs` (Context) is explicit that no
     DACL-based equivalent of that check exists yet — this is it. Failing to
     apply the DACL is a hard install/startup failure, not a logged warning.
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
     the canonicalization finding in Context. `current` is briefly absent
     during the swap itself (Decision 4's symlink-replacement mechanism cannot
     be a single atomic rename on Windows); a reader that finds it absent
     must not assume day-0 on that basis alone — it must fall back to reading
     the service's actual `binPath` (`sc qc`) to tell "day 0, never promoted"
     apart from "mid-promotion, check again."

4. **Promotion mechanics**: `apply-release` (the same one-shot, operator/timer/
   scheduler-invoked command ADR-0015's amendment describes, extended to dispatch
   on `cfg(windows)`) does, after staging and verifying `versions\vN\` the same
   way as Linux (Decision 2's shared manifest/verification code path):
   1. **Pre-flight launch check**: runs the staged `versions\vN\watchdog.exe`
      with a dedicated, side-effect-free self-check subcommand (exits 0 and
      prints nothing that needs parsing — existence of the exit code is the
      whole check) before touching `binPath` or `current` at all. A release
      that fails this — corrupted binary, missing dependency, wrong
      architecture — is rejected the same way a bad signature is (Decision 5's
      `Failed` outcome, `versions\vN\` left on disk for inspection, nothing
      live touched). This is the actual fix for "a broken release reaches
      `binPath`" (reviewed finding on Decision 6): it is cheaper and more
      certain to never promote an unlaunchable binary than to depend on
      exactly how the SCM's failure actions treat a launch failure versus a
      post-launch crash, which (Decision 6) is not fully settled.
   2. `sc config SynthaEDR binPath= "<versions\vN\watchdog.exe resolved> run
      --agent-bin <versions\vN\agent.exe resolved> --alerts <alerts path>"` —
      same `build_bin_path` format, same canonicalize-before-persist posture
      `cmd_install` already uses, just computed against the new version's
      resolved paths instead of the MSI's. Bracketed by ACL reset/reharden
      (below) exactly like `cmd_install`'s own `sc description`/`sc failure`
      calls (Context). A failure here is a **hard failure** (Decision 5's
      `Failed` outcome, surfaced, never a logged warning): `current` has not
      moved yet (step 3), so the service is still consistently on the old
      version on both counts — never the "`current` says vN, `binPath` says
      old" lie this ordering exists to prevent. This reverses the step order
      an earlier draft of this ADR had (`current` flipped first); flipping
      `current` before `sc config` could succeed leaves exactly that lie live
      if `sc config` is then denied or power is lost before it runs.
   3. **ACL reset/reharden is unconditional**, not best-effort around step 2:
      `reset_service_acl_best_effort()` runs, then `sc config` (whatever it
      returns), then `harden_service_acl()` always runs before the result is
      inspected — a small RAII guard (or equivalent) that calls
      `harden_service_acl()` on drop regardless of how step 2 returned, so an
      early `?` can never leave the service on the permissive SDDL
      (reviewed finding: `cmd_install`'s existing bracket has exactly this gap
      today and needs the same fix, not just this ADR's new call site).
      Rehardening's own failure is itself a hard failure, logged and surfaced,
      never swallowed — losing the #71 self-protection ACL silently is worse
      than a failed promotion. Both ACL functions move from
      `watchdog/src/service/windows.rs` into `updater`'s own Windows layout
      module: `updater` is a leaf crate (`tools/check-deps.py`'s LEAF tier,
      base-tier dependencies only), so it cannot depend on `watchdog` (a
      *binary*, Context) for them — the dependency the earlier draft waved at
      would be backwards. `watchdog` (free to depend on anything, being a
      binary) calls them from `updater` instead of owning them; `cmd_install`
      changes its two call sites accordingly. No behavior change, just which
      crate the functions live in.
   4. Only now flips `current` to `versions\vN\`: `RemoveDirectoryW` on the
      existing `current` reparse point (removes the link itself, never
      recurses into whatever it points at — ordinary NTFS reparse-point
      semantics, not special-cased here) followed by `MoveFileExW` (no
      `MOVEFILE_REPLACE_EXISTING` needed or wanted — the name is now free) of a
      freshly built `current.tmp` symlink into `current`. This is **not** the
      single atomic `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` rename
      ADR-0015 Decision 5 relies on for Linux: that call fails with
      `ACCESS_DENIED` when the destination is an existing directory, reparse
      point or not (reviewed finding on this ADR) — a plain file-over-file
      rename it is not. The gap between the two calls is real but small and
      already accounted for: Decision 3 has `current`'s readers fall back to
      `binPath` when it is absent, precisely for this window; `binPath` itself
      (step 2) already points at vN before this step runs, so nothing is
      misreported in between, only momentarily unavailable from `current`.
   5. Restarts the service (`sc stop` then `sc start`, or `ControlService` plus
      the existing `sc failure` auto-restart — either is fine, this ADR does not
      pin the exact restart primitive down) so the new `binPath` takes effect; the
      currently-running old-version watchdog process keeps running from its own
      open file handle until this restart actually happens (Context), so there is
      no window where the service is simultaneously "promoted" and "running
      neither version."

   **MSI upgrade and uninstall**: a plain uninstall leaves
   `%ProgramData%\Synthaea\` (state, `current`, `versions\`,
   `banned_versions.json`) in place, the same deliberate posture as the
   RPM packaging fix on #861 (a plain uninstall does not wipe data on any
   platform this project packages for) — this ADR does not reopen that. The
   consequence is the installer's job, not the updater's: both a major-upgrade
   and a fresh install over a previous uninstall must leave the service's
   `binPath` pointing at the freshly-written `Program Files\Synthaea\`
   binaries, exactly as a true first install does, **never** trusting a
   leftover `current`/`banned_versions.json` from before — the MSI's own
   install sequence (not `apply-release`) is what runs `cmd_install` fresh on
   every one of these paths already, so this is a statement of required
   behavior for that existing sequence (verify it, Decision 4 does not change
   it) rather than new code this ADR introduces. A stale `current` then simply
   sits unread until the next `apply-release` promotion overwrites it; nothing
   reads it as authoritative over a freshly-set `binPath` (Decision 3).

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
   (`%ProgramData%\Synthaea\banned_versions.json`), flips `current` back
   (Decision 4's `RemoveDirectoryW`-then-`MoveFileExW` pair, same as a
   promotion), and exits non-zero so `sc failure`'s configured restart action
   relaunches from the rolled-back `binPath` — this depends on `cmd_install`
   also calling `sc failureflag SynthaEDR 1` (Decision 6): by default the SCM
   ignores a clean non-zero exit entirely and only queues failure actions for
   a crash, so without that flag this rollback would leave the service simply
   stopped, not relaunched. On success, the watchdog writes `.healthy` and
   prunes releases older than the rollback target, same as Linux (ADR-0015
   Decision 8/amendment) — except a prune that hits a sharing violation
   (`ERROR_SHARING_VIOLATION`, e.g. a lingering handle from a process that
   hasn't fully exited yet) is logged and left for the next successful
   health-check cycle to retry, never treated as a rollback failure: pruning
   is bookkeeping, not correctness, and the rule it already follows (never
   prune `current`'s target or anything newer) already keeps it from ever
   trying to delete something still in use by design, only by lingering OS
   state.

6. **Failure recovery: `sc failure`'s own `run` action, not a new mechanism.**
   Linux's safety net for "the thing `ExecStart` points at cannot even exec" is
   `ExecStartPre=.../bootstrap/watchdog recover`, always run by systemd before
   every service start attempt, including every automatic restart. The SCM has no
   `ExecStartPre` equivalent, but `sc failure` already supports a fourth action
   type beyond `restart`/`reboot`/`none`: `run`, which launches the program given
   by that same call's `command=` parameter
   ([Microsoft: "Set up recovery actions to take place when a service
   fails"](https://technet.microsoft.com/en-us/library/cc738230(v=ws.10));
   `sc failure dfs reset= 60 command= c:\path\restart_dfs.exe actions=
   run/5000` is Microsoft's own example pairing). Three corrections to
   `cmd_install`'s existing `sc failure`/`sc failureflag` setup are needed for
   this to actually work (all three are reviewed findings on this ADR, not
   implementation polish — explained below):

   - **`reset=` must be a real window, not `0`.** `cmd_install` (Context)
     today calls `sc failure` with `reset= 0 actions=
     restart/5000/restart/5000/restart/5000`. `reset=` is the number of
     seconds of failure-free running after which the SCM zeroes the failure
     count back to 0; at `0` that happens effectively immediately, so the SCM
     never sees "the 2nd failure" or "the 3rd failure" — every failure is
     "the 1st," and the actions list never advances past its first entry.
     This changes to `reset= 60` (comfortably longer than three 5-second
     restart delays), matching Microsoft's own documented example above, so
     three failures inside that window actually exhaust the list and reach
     the fourth, newly-appended slot:
     `restart/5000/restart/5000/restart/5000/run/5000`, with `command=
     "<Program Files\Synthaea\watchdog.exe> recover"` — **the
     install-directory copy specifically, never `versions\vN\`'s or
     `current`'s resolved path**, because that path is "package-owned, never
     touched by the updater" (Context) and therefore the one binary that
     cannot itself be the broken thing a crash-looping `binPath` is pointing
     at. `command=` is set once at `cmd_install` time and is not rewritten on
     promotion, unlike `binPath` (Decision 4).
   - **`sc failureflag SynthaEDR 1` must also be set**
     ([Microsoft: "Sc failureflag"](https://technet.microsoft.com/en-us/cc742011);
     background on the flag's effect:
     [Stephen Cleary, "ServiceBase Gotcha: Recovery
     Actions"](https://blog.stephencleary.com/2020/06/servicebase-gotcha-recovery-actions.html)).
     Without it the SCM only queues failure actions when the service
     terminates *without* reporting `SERVICE_STOPPED` (a crash); a watchdog
     that reports a clean stop with a non-zero exit code — exactly what
     Decision 5's rollback path does — is otherwise ignored entirely, leaving
     the service simply stopped instead of relaunched from the rolled-back
     `binPath`. This is one more `cmd_install`-time call, bracketed by the
     same ACL reset/reharden pair as the rest of its setup (Decision 4).
   - The pre-flight launch check **added to `apply-release` in Decision 4**
     is the actual fix for the common case this decision exists to cover — a
     bad release reaching `binPath` — by never letting it happen rather than
     by recovering after the fact. What remains genuinely **open**, and is
     not resolved by research for this ADR: whether the SCM's configured
     failure actions fire at all for a `binPath` that fails to even launch
     (`CreateProcess` erroring before the service process exists) the same
     way they fire for a service that starts and later crashes or stops with
     an error — Microsoft's own documentation does not say so explicitly, and
     this needs an empirical test (corrupt a `versions\vN\watchdog.exe` on a
     real Windows host, past the pre-flight check somehow, and watch whether
     `run/5000` actually fires) before this slice ships. If it does not fire,
     `recover` as designed here only ever helps with post-launch failures (a
     crash after `.healthy` is set, say, from file corruption on disk after
     promotion) and the launch-failure case stays covered solely by the
     pre-flight check's prevention, not by this decision's recovery.
   `recover`'s job is exactly `Layout::rollback_target`'s
   existing logic (Decision 5) with no manifest/health-check context available by
   construction (this path exists because the health-check watchdog process
   itself may never get far enough to run): reset `binPath` to the newest
   `versions\vN\` with `.healthy` set and not banned, or `Program Files\Synthaea`
   with none, then start the service.
   **Still open**: whether `recover` bans the version it is recovering away
   from (banning on a start failure the same way Decision 5 bans on a
   health-check failure would stop the crash-loop in 3 restarts instead of
   forever re-promoting the same broken release after every reboot, but needs
   its own reasoning about false positives from, say, a transient disk-full
   at exec time), and the exact `command=` string quoting/escaping for a path
   containing spaces (`Program Files`) through `sc`'s own `/`-delimited
   `actions=` parsing, are implementation questions for whoever builds this
   slice, not answered by this ADR. All three corrections above
   (`reset=`, `failureflag`, the `run` slot) are changes to `cmd_install`'s
   existing `sc failure`/`sc failureflag` setup, run once at install time
   inside the reset-then-reharden bracket that is already there (not a new
   one) — none of this is part of `apply-release`'s per-promotion steps.

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
- `reset_service_acl_best_effort`/`harden_service_acl` move from
  `watchdog/src/service/windows.rs` into `updater`'s Windows module (Decision
  4); `watchdog`'s `cmd_install` becomes a caller of `updater`, not the owner
  of these two functions — the only direction `tools/check-deps.py`'s LEAF
  tier allows, since `updater` cannot depend on a binary. `cmd_install`
  itself also changes behaviorally, not just by relocation: `reset= 60`
  instead of `0`, and a new `sc failureflag SynthaEDR 1` call (Decision 6).
- `%ProgramData%\Synthaea\` gains a DACL it did not have before (Decision 3)
  — the first piece of Windows-side code in this project to set one
  explicitly rather than rely on inherited defaults.
- First cross-platform exercise of the ADR-0015 manifest format: the build-time
  path normalization in Decision 2 is a small, real change to `release-tool`,
  and needs a fixture proving a manifest built with it still verifies
  identically on both platforms' `Layout`.
- Signing/Authenticode (packaging/windows/README.md's "not yet decided") remains
  exactly as unresolved as before — this ADR does not depend on it and does not
  resolve it.

## Deferred

- **`watchdog.exe recover`'s own logic and the `command=` path-quoting
  detail** (Decision 6) — the trigger mechanism itself (`sc failure`'s `run`
  action, with a corrected `reset=`/`failureflag` and a `command=` pinned to
  the `Program Files` copy) is identified, not a gap this slice leaves fully
  open; what `recover` does once invoked, and whether it bans the version it
  recovers away from, still needs writing.
- **Whether the SCM's configured failure actions fire for a launch failure
  (`CreateProcess` erroring) the same way they fire for a post-launch crash**
  (Decision 6) — genuinely unresolved by documentation, needs an empirical
  test on a real Windows host before this slice ships. The pre-flight launch
  check added to `apply-release` (Decision 4) covers the common case
  (a bad release) regardless of the answer; a `binPath` broken by some other
  means after a successful promotion (disk corruption, antivirus quarantine)
  is the part that would stay uncovered if the answer turns out to be no.
- **macOS binary self-update** — no packaging exists yet at all; ADR-0015's
  Deferred entry for it is unchanged.
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
