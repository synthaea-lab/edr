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
- **`%ProgramData%\Synthaea\` is the right place for the updater's mutable
  state, but nothing creates or owns it in production today — this ADR is
  what does.** The only existing reference is a *test* fixture
  (`watchdog/src/service/windows.rs:347`'s `--alerts` default resolving to
  `C:\ProgramData\Synthaea\alerts.ndjson`); in a real install, the MSI passes
  `--alerts "[INSTALLFOLDER]alerts.ndjson"` (`Product.wxs:92`), so today's
  actual alerts file lives in `Program Files\Synthaea`, not `ProgramData`.
  `Program Files\Synthaea` stays the
  right place for the install itself regardless — admin-write-protected by
  default ACLs, the same "package-owned, never touched by the updater"
  property Linux's `bootstrap/` has by virtue of package ownership
  (`packaging/linux`'s systemd unit never writes there either) — but
  `%ProgramData%\Synthaea\` is a new directory this ADR introduces for the
  updater's own state (`versions\`, `current`, `banned_versions.json`), not
  a pre-existing convention it merely adopts. Decision 3 below is explicit
  about who creates it, with what DACL, and when.
- **NTFS directory symlinks are available and transparently followed.** The
  service runs as `LocalSystem`, which holds every privilege including
  `SeCreateSymbolicLinkPrivilege` — unlike an unprivileged user, who needs
  Developer Mode enabled to create one. Swapping what a *directory* symlink
  points at is **not** a single atomic rename the way Linux's `rename(2)`
  replaces a symlink (ADR-0015 Decision 5's guarantee): `MoveFileExW(...,
  MOVEFILE_REPLACE_EXISTING)` fails with `ACCESS_DENIED` when the destination
  is an existing directory, reparse point or not — confirmed against Wine's
  own test suite and Git for Windows's `mingw_rename`, which special-cases
  exactly this error; Decision 4 below has the actual two-step mechanism
  this requires. What *is* still true and still
  load-bearing: a running process keeps its own image mapped by handle, not
  by path — Windows allows renaming (not overwriting) a file a process has
  open from it, so the old target's `watchdog.exe` stays safely runnable
  throughout the swap, the same property Linux's design already relies on;
  only the swap of the *symlink itself* needs the two-step mechanism.
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
   replacing any part of it. The minifilter driver (`SynthaeaFilter.sys`) is
   explicitly **not** part of this binary pair, and this ADR does not cover
   updating it — a kernel driver's own signing/install path (WHQL, a
   reboot-capable INF-based install) is a different, heavier mechanism than
   swapping two usermode EXEs, and designing it is out of scope here; see
   Deferred for the consequence of leaving this gap open. macOS binary
   self-update remains unimplemented and
   undesigned (ADR-0015 Deferred still applies there). Content distribution is out
   of scope here exactly as it was in ADR-0015.

2. **Manifest shape and signature: unchanged, reused as-is.** The same
   `ReleaseManifest` envelope (`schema_version`, monotone `release_version`,
   `entries: BTreeMap<PathBuf, String>`, Ed25519 signature via `ring`) that
   ADR-0015 Decision 2 defined. One difference: normalization happens once, at
   **build time**, in `release-tool` — never at verify time, and never
   per-platform. A manifest key is always relative (ADR-0015 Decision 2), so
   `release-tool` rejects a candidate entry outright (refuses to build the
   manifest, not a warning) if its path contains a `..` segment, a backslash
   (a legal filename character on Linux, so rewriting it to forward slash on
   read could make two different signed-over paths collide or resolve
   differently from what was actually signed), **any colon at all** — not
   only an alternate-data-stream name but a drive letter too, since a
   relative key has no legitimate reason to carry one: an earlier version of
   this rule exempted a colon at a drive letter's second character, which let
   `C:evil.dll` straight through — `versions\vN\` joined with it is a
   drive-relative path that lands outside the staged directory entirely.
   That exemption is removed; any entry starting with a drive letter or a
   backslash (an absolute or rooted path) is rejected the same way, alongside
   a `\\?\`-prefixed or UNC form, or a component that is (case-insensitively,
   with or without an extension) one of the Windows reserved device names
   (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`) or ends in a
   trailing dot or space (both are silently stripped by Windows's own path
   normalization, so `agent.exe.` and `agent.exe` name the same file on NTFS
   even though they differ as manifest keys). `release-tool` also rejects the
   whole manifest if any two entries collide case-insensitively (`Agent.exe`
   and `agent.exe`): the manifest is signed once on a case-sensitive build
   host, but Windows's `Layout` looks entries up case-insensitively (NTFS's
   own default collation) — the two verify as distinct entries on Linux and
   collapse onto one file on NTFS, so the hash actually checked may not be
   the hash of the file actually executed. What survives is stored as a
   forward-slash string, exactly as ADR-0015 Decision 2 already did.
   **8.3 short names are a related, narrower residual risk the checks above
   do not close**: two long names that differ (`Agent-v2.exe`,
   `Agent-v3.exe`) can still generate the same legacy 8.3 short name
   (`AGENT~1.EXE`) if short-name generation is enabled on the volume, and
   either one could then be opened through the other's short name. Closing
   this at the manifest level would mean reimplementing Windows's 8.3
   generation algorithm in `release-tool` just to reject collisions against
   it; cheaper and more certain is for `cmd_install` to disable short-name
   generation on `%ProgramData%\Synthaea\versions\` itself (`fsutil
   8dot3name set <path> 1`, supported per-directory since Windows
   8/Server 2012) before `apply-release` ever stages a file under it, as a
   hard install failure if it cannot be disabled — the same "hard-fail, do
   not silently proceed" posture Decision 3's squatting defense already
   takes.
   This check has a real, already-shipped bug to fix before it means
   anything: `release-tool/src/manifest_dir.rs`'s `walk()` joins each
   directory entry into a relative path (`relative.join(name)`) and then
   unconditionally rewrites every backslash to a forward slash (`:54`,
   `p.replace('\\', "/")`) *before* `validate_entry_paths()` ever sees the
   string (`build()` calls it last, on the already-rewritten map) — so the
   backslash rule above can never fire: a literal backslash inside one
   filename (legal on Linux) is silently turned into an extra path
   separator, manufacturing a signed-over entry that never existed on disk,
   exactly the collision this rule exists to prevent. The fix is to validate
   each `name` from `read_dir` on its own, as a single untouched component,
   before it is joined or slash-normalized at all — not to validate the
   final string, which by construction can no longer contain the thing being
   rejected.

3. **Layout**: `updater::layout` grows a Windows-native sibling, not a
   `cfg`-abstracted trait with two bodies — the two platforms' primitives
   (symlink + `rename(2)` vs. `CreateSymbolicLinkW` + `MoveFileExW`, plus the
   `sc config` step Decision 4 below adds) differ enough that one shared
   abstraction would hide more than it clarifies, matching this crate's existing
   `#[cfg(target_os = "linux")]`-gated-module convention (ADR-0015 Consequences)
   rather than inventing a cross-platform API surface that would misleadingly
   suggest parity.
   - **Base directory**: `%ProgramData%\Synthaea\` (a new directory this ADR
     introduces — see Context) — created and ACL'd by `cmd_install`
     specifically (not the MSI's `Directory`/`CreateFolder` table, which
     touches nothing under `ProgramData` today), since `cmd_install` is
     already the one step that runs on every install path that matters here:
     a true first install, a major upgrade, and a fresh install over a
     previous uninstall alike (see "MSI upgrade and uninstall" below). The
     DACL is **protected and non-inherited** (`SetSecurityInfo` with
     `PROTECTED_DACL_SECURITY_INFORMATION`, or the SDDL equivalent), owner
     set explicitly to `BUILTIN\Administrators`, granting write access only
     to `SYSTEM` and `BUILTIN\Administrators` — never inherited from
     `%ProgramData%`'s own default ACL, which grants `BUILTIN\Users`
     create-subfolder rights on a stock install, and never left to whatever
     owner a pre-existing directory happens to have (see squatting defense
     below). This is **required**, not best-effort: the service runs the
     binaries under it as `LocalSystem` (Context), so a writable-by-everyone
     `versions\vN\` is the same plant-then-`sc config`-runs-it-as-SYSTEM path
     the Linux design's world-writable-directory check exists to close, and
     the `#103` comment already in `watchdog/src/service/windows.rs`
     (Context) is explicit that no DACL-based equivalent of that check exists
     yet — this is it. Failing to apply the DACL is a hard install/startup
     failure, not a logged warning.
     **Squatting defense:** a non-admin can
     pre-create `%ProgramData%\Synthaea\` before the MSI ever runs —
     ordinary `BUILTIN\Users` rights on `%ProgramData%` allow it — and an
     owner keeps `WRITE_DAC` over what they created, so merely *setting* a
     DACL on an existing directory is not enough; the owner could grant
     themselves access back. `cmd_install` must therefore: refuse and fail
     hard if the path exists and is **not** already owned by `SYSTEM` or
     `BUILTIN\Administrators` (never silently take ownership and proceed —
     that is exactly the TOCTOU this defense exists to close); refuse and
     fail hard if the path is a reparse point of any kind (a symlink or
     junction here could redirect every write somewhere attacker-controlled);
     and re-verify owner, DACL, and reparse-point-freedom on **every**
     `apply-release` run, not only the first time the directory is created —
     a correct DACL today says nothing about tomorrow.
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
      `binPath`": it is cheaper and more
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
      old" lie this ordering exists to prevent: flipping `current` before
      `sc config` succeeds would leave exactly that lie live if `sc config`
      is then denied or power is lost before it runs, so `sc config` must
      run first.
   3. **ACL reset/reharden is unconditional**, not best-effort, and brackets
      both step 2 and step 5 below in one continuous window — not two
      separate brackets: `reset_service_acl_best_effort()` runs once, before
      step 2; `harden_service_acl()` runs once, after step 5, via a small
      RAII guard (or equivalent) that calls it on drop regardless of how
      steps 2-5 returned, so an early `?` anywhere in between can never
      leave the service on the permissive SDDL — `cmd_install`'s existing
      bracket has exactly this gap today and needs the same fix, not just
      this ADR's new call site. Extending the
      bracket over the restart (step 5) is itself required, not cosmetic —
      see step 5's own note below.
      Rehardening's own failure is itself a hard failure, logged and
      surfaced, never swallowed — losing the #71 self-protection ACL
      silently is worse than a failed promotion. **This is a real behavior
      change, not just a relocation**: `harden_service_acl()` as it exists today
      (`watchdog/src/service/windows.rs:163`) only logs a warning and
      continues on failure; every call site, including `cmd_install`'s
      existing two, now hard-fails instead. That is the intended fix, not an
      accident of the move, and is called out here so it is not mistaken
      for implementation detail.
      Both ACL functions move from `watchdog/src/service/windows.rs` into
      `updater`'s own Windows layout module: `updater` is a leaf crate
      (`tools/check-deps.py`'s LEAF tier, base-tier dependencies only), so it
      cannot depend on `watchdog` (a *binary*, Context) for them — that
      dependency direction would be backwards. `watchdog`
      (free to depend on anything, being a binary) calls them from `updater`
      instead of owning them; `cmd_install` changes its two call sites
      accordingly. One more required change comes with the move: `run_sc`
      and both ACL functions currently return `anyhow::Result` (fine in
      `watchdog`, a binary), but `updater` is a library crate, and this
      project's error convention (`CLAUDE.md`) is `thiserror` there —
      `UpdaterError` gains a variant for an `sc` invocation that fails to
      launch or returns non-zero, and these functions return that instead of
      `anyhow::Result` once they live in `updater`.
   4. Only now flips `current` to `versions\vN\`: `RemoveDirectoryW` on the
      existing `current` reparse point (removes the link itself, never
      recurses into whatever it points at — ordinary NTFS reparse-point
      semantics, not special-cased here) followed by `MoveFileExW` (no
      `MOVEFILE_REPLACE_EXISTING` needed or wanted — the name is now free) of a
      freshly built `current.tmp` symlink into `current`. This is **not** the
      single atomic `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` rename
      ADR-0015 Decision 5 relies on for Linux: that call fails with
      `ACCESS_DENIED` when the destination is an existing directory, reparse
      point or not — a plain file-over-file rename it is not. The gap between the two calls is real but small and
      already accounted for: Decision 3 has `current`'s readers fall back to
      `binPath` when it is absent, precisely for this window; `binPath` itself
      (step 2) already points at vN before this step runs, so nothing is
      misreported in between, only momentarily unavailable from `current`.
   5. **Restarts the service with `sc stop` then `sc start`, explicitly —
      not `ControlService` plus the existing `sc failure` auto-restart.**
      They are not equivalent: a deliberate stop is not a service *failure*,
      so `sc failure`'s configured actions — the restart ladder Decision 6
      relies on — never fire for it; relying on that path here would leave
      the service simply stopped. The other reason this step must run
      inside step 3's ACL bracket rather than after it: the hardened SDDL
      (`watchdog/src/service/windows.rs:150`) grants `BA` (built-in
      Administrators) `RP` (`SERVICE_START`) but not `WP` (`SERVICE_STOP`),
      so an `apply-release` invoked by an administrator (Decision 4's own
      "operator/timer/scheduler-invoked", Context) cannot `sc stop` a
      hardened service at all — only `SY` can. Running the stop inside the
      permissive window step 3 already opens for `sc config` costs nothing
      extra (the bracket is already there) and is the only way this step
      works for a non-SYSTEM caller. The currently-running old-version
      watchdog process keeps running from its own open file handle until
      this restart actually happens (Context), so there is no window where
      the service is simultaneously "promoted" and "running neither
      version."
      **The SCM reads the exit code from `SetServiceStatus`, not the
      process's own exit code** — `dwWin32ExitCode` (or
      `dwServiceSpecificExitCode` with `dwWin32ExitCode` set to
      `ERROR_SERVICE_SPECIFIC_ERROR`), reported when the service transitions
      to `SERVICE_STOPPED` on handling `SERVICE_CONTROL_STOP`. This matters
      here because `cmd_install` sets `failureflag= 1` (Decision 6), which
      makes the SCM queue a failure action for *any* stop reported with a
      non-zero code, deliberate or not: the watchdog's own
      `SERVICE_CONTROL_STOP` handler must report `ERROR_SUCCESS` for this
      explicit `sc stop`, or the restart ladder's `run`/`restart` action
      fires and races the `sc start` this step issues next. A failed
      rollback (Decision 5) is the opposite case and must report non-zero on
      purpose — the two paths share the mechanism and must not share the
      exit code.

   **MSI upgrade and uninstall:** `Product.wxs`'s own custom action runs `rd
   /s /q` on the install folder because, on this platform, "uninstall must
   be clean and complete" (the comment directly above it) — a stricter
   posture than the RPM precedent on #861, which this ADR does not carry
   over to Windows. `%ProgramData%\Synthaea\` is untouched by that action,
   so a plain uninstall leaves it behind; left alone across a reinstall,
   that stale state is not inert, because `Layout::rollback_target` and
   `recover` (Decision 5/6) read `versions\` and `.healthy` directly, and the
   self-integrity monitor (`agent/src/integrity.rs:51`) reads `current` — so
   an operator who uninstalls a bad release's MSI and reinstalls an older
   one to escape it would hit a `recover`/health-check path that still sees
   the newer, "healthier" `versions\v9\` left over from before, and "rolls
   back" forward into the very release the reinstall was trying to escape,
   while the integrity monitor hashes a `current` target that is not what
   `binPath` on the freshly-reinstalled MSI actually runs.
   **Decided here: `cmd_install` clears the updater's own state on every
   install path it runs on** — true first install, major upgrade, and a
   fresh install over a previous uninstall alike (it already runs fresh on
   all three, per Context) — removing `versions\`, `current`, `.healthy`
   markers, and `banned_versions.json` under `%ProgramData%\Synthaea\`
   before recreating the directory and its DACL (Decision 3). This keeps the
   invariant simple and checkable (every `cmd_install` run starts from
   exactly "day 0, running from `Program Files\Synthaea`, no staged
   versions") instead of asking every reader of that state to separately
   reason about how stale it might be. A plain uninstall by itself still
   leaves `%ProgramData%\Synthaea\` behind (Windows's uninstaller has no
   custom action targeting it, same as today), but the next `cmd_install` —
   whether from a reinstall of the same MSI or a different one — resets it,
   so leftover state never outlives the service's own next install.

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
   promotion), and reports `SERVICE_STOPPED` with a non-zero
   `dwWin32ExitCode` via `SetServiceStatus` (Decision 4 step 5's exit-code
   note) so `sc failure`'s configured restart action relaunches from the
   rolled-back `binPath` — this depends on `cmd_install` also calling `sc
   failureflag SynthaEDR 1` (Decision 6): by default the SCM ignores a clean
   stop reported with a non-zero code entirely and only queues failure
   actions for a crash, so without that flag this rollback would leave the
   service simply stopped, not relaunched. On success, the watchdog writes `.healthy` and
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
   this to actually work, not implementation polish:

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
   `recover`'s job is `Layout::rollback_target`'s existing logic (Decision
   5), applied against the version that is actually failing, not just "the
   newest healthy one": picking the newest `.healthy`-and-not-banned version
   with no reference point would, if the *currently* running version —
   already marked `.healthy` from an earlier successful promotion — is the
   one now crashing (corrupted on disk after the fact, say), still call that
   "the newest healthy one" and re-select exactly the broken version on
   every restart, crash-looping forever instead of recovering. `recover`
   instead: reads the service's current `binPath` (`sc qc`) to identify
   which `versions\vN` (or `Program Files\Synthaea`, meaning no staged
   version) is the one that just failed to come up; **bans that version**
   in `banned_versions.json` if it is a staged version (this also resolves
   the "still open" question below — a start failure bans the same way a
   health-check failure already does in Decision 5, for the same reason:
   without it, a reboot re-promotes the identical broken release and the
   crash-loop just restarts itself one `sc failure` cycle later); then calls
   `rollback_target` with that failing version's number, getting back a
   strictly older `versions\vN` with `.healthy` set and not banned, or
   `Program Files\Synthaea` if none qualifies; rewrites `binPath` to that
   target (the same `sc config`-bracketed-by-ACL pair as a promotion); and
   starts the service.
   **When `binPath` already points at `Program Files\Synthaea` itself** —
   the install-directory copy is the one crashing, from antivirus
   quarantine or on-disk corruption, say — there is no older target:
   `rollback_target` has nothing to return, and banning the install
   directory would ban the one thing Decision 3's "package-owned, never
   touched by the updater" posture depends on staying unbanned. `recover`
   does not ban it and does not loop looking for an alternative; it logs
   this at error level as a terminal, updater-cannot-help-further condition
   and starts `Program Files\Synthaea\watchdog.exe` again as-is — the best
   available action, since that binary is still the one the MSI installed
   and verified, and the actual fix (repairing or reinstalling the MSI) is
   an operator action outside this mechanism's scope. This has no
   manifest/health-check context available by construction (this path
   exists because the health-check watchdog process itself may never get
   far enough to run), but reading `binPath` directly needs none.
   **Still open**: the exact `command=` string quoting/escaping for a path
   containing spaces (`Program Files` always has one) through `sc`'s own
   `/`-delimited `actions=` parsing is an implementation question for
   whoever builds this slice, not answered by this ADR. A transient failure
   unrelated to the release itself (disk-full at exec time, say) would
   still get banned by this logic — the same false-positive exposure
   Decision 5's health-check ban already accepts, not a new risk this
   introduces. All three corrections above (`reset=`, `failureflag`, the
   `run` slot) are changes to `cmd_install`'s existing `sc
   failure`/`sc failureflag` setup, run once at install time inside the
   reset-then-reharden bracket that is already there (not a new one) —
   none of this is part of `apply-release`'s per-promotion steps.

## Consequences

- `updater::layout` gains a Windows module (`#[cfg(target_os = "windows")]`),
  parallel to, not sharing a trait with, the Linux one — new code, not a
  refactor of the existing Linux path.
- **This ADR widens `CLAUDE.md`'s `updater` platform-code exception**, which
  today scopes the crate's `#[cfg(target_os = ...)]` code to ADR-0015's
  Linux-first slice and says Windows "need[s] its own design" first — the
  exception's own text should name this ADR's job once it exists, rather
  than leaving a future reader to wonder whether the Windows module it names
  is actually sanctioned. This PR amends that paragraph; the scope stays
  narrow — this ADR's own
  layout/promotion logic, not a general invitation for `updater` to grow
  unrelated platform branches.
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
  4), returning `UpdaterError` instead of `anyhow::Result` once there
  (library-crate convention); `watchdog`'s `cmd_install` becomes a caller of
  `updater`, not the owner of these two functions — the only direction
  `tools/check-deps.py`'s LEAF tier allows, since `updater` cannot depend on
  a binary. `cmd_install` itself also changes behaviorally, not just by
  relocation: `reset= 60` instead of `0`, a new `sc failureflag SynthaEDR 1`
  call (Decision 6), and rehardening failure becomes a hard error instead of
  a logged warning (Decision 4).
- `%ProgramData%\Synthaea\` gains a DACL it did not have before (Decision 3)
  — the first piece of Windows-side code in this project to set one
  explicitly rather than rely on inherited defaults — plus an
  ownership/reparse-point check `cmd_install` and every `apply-release` now
  both run against it, and a state wipe `cmd_install` performs on every
  install path (Decision 4's "MSI upgrade and uninstall").
- First cross-platform exercise of the ADR-0015 manifest format: the build-time
  path normalization in Decision 2 is a small, real change to `release-tool`,
  and needs a fixture proving a manifest built with it still verifies
  identically on both platforms' `Layout`.
- Signing/Authenticode (packaging/windows/README.md's "not yet decided") remains
  exactly as unresolved as before — this ADR does not depend on it and does not
  resolve it.

## Deferred

- **The `command=` path-quoting detail** (Decision 6) — the trigger
  mechanism and `recover`'s own logic are both decided there; only the
  exact `command=` string quoting/escaping for a path containing spaces
  through `sc`'s `/`-delimited `actions=` parsing is left as an
  implementation detail.
- **Whether the SCM's configured failure actions fire for a launch failure
  (`CreateProcess` erroring) the same way they fire for a post-launch crash**
  (Decision 6) — genuinely unresolved by documentation, needs an empirical
  test on a real Windows host before this slice ships. The pre-flight launch
  check added to `apply-release` (Decision 4) covers the common case
  (a bad release) regardless of the answer; a `binPath` broken by some other
  means after a successful promotion (disk corruption, antivirus quarantine)
  is the part that would stay uncovered if the answer turns out to be no.
- **Minifilter driver/agent protocol-version skew across an update**
  (Decision 1) — the driver refuses a client whose protocol version differs
  (`PROTOCOL_VERSION`, checked in `SynthaeaFilter.c` around L1397). If an
  `agent.exe` promoted by this ADR's mechanism bumps that version without a
  matching driver update (which this ADR does not cover — Decision 1), the
  agent loses file telemetry while the heartbeat health check, which only
  measures liveness, keeps passing — a release that is silently degraded,
  not failed, and `.healthy`/promotion proceed as if nothing were wrong.
  Closing this needs either the manifest or the pre-flight check (Decision
  4) to carry the minifilter protocol version a release requires and refuse
  promotion on a mismatch against the live driver's reported version — not
  designed here, since it depends on how (or whether) driver updates get
  their own mechanism first.
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
