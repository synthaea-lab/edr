# ADR-0042: Response Remediation and Rollback

- **Status**: proposed
- **Date**: 2026-10-29

## Context

Response (issue #25) implements three containment actions — kill, quarantine, isolate —
and issue #133 asks for the recovery half: every destructive response reversible, and
attacker persistence removable, scoped to the case's damage, policy-gated and audited
exactly like response itself. That premise needs checking against what already exists,
because the three actions are not equally unowned:

- **Quarantine restore already exists, fully wired.** `unquarantine` (`crates/response/
  src/quarantine.rs`) restores a quarantined file to its original path, verifies the hash
  before returning it, restores the original Unix mode from the `.origin` sidecar, and
  never overwrites an occupied destination. `agent quarantine restore`
  (`agent/src/quarantine_cmd.rs`, `cmd_quarantine_restore`) wires it end to end, audited as
  `RESPONSE-UNQUARANTINE` into `alerts.ndjson` on both success and failure, with tests for
  the half-done-cleanup cases. It is not policy-gated: only host access is needed.
- **Isolation lift is library-complete, with zero wiring.** `lift_isolation`
  (`crates/response/src/isolation.rs`) exists, is fully tested, and is deliberately never
  policy-gated (ADR-0037 §4: lifting is the safe direction). Its result type is documented
  as feeding a `HOST-UNISOLATE` audit line, the counterpart of `HOST-ISOLATE`, but nothing
  outside `crates/response` calls it and no binary emits either line. ADR-0037 is itself
  still **proposed**, and its own text defers the binary-side wiring ("the firewall itself
  is injected by the binary", `crates/response/src/lib.rs`). Applying isolation isn't
  live in the shipped agent yet, so neither is lifting it.
- **Kill has, and needs, no undo.** Not a gap; out of scope by the issue's own framing.
- **Persistence removal has detection, not removal.** `crates/rules/src/stateless.rs`
  already detects scheduled tasks (T1053.005, `check_scheduled_task_persistence`),
  services (T1543.003, `check_service_install_persistence`), account creation
  (T1136.001), systemd units, macOS launch items, and the shell-profile/cron/LaunchAgents
  path family. Several of these rules' doc comments name the manual command an analyst
  runs today (`schtasks /Delete /TN <name> /F`, `sc.exe delete <name>`,
  `net user <name> /delete`). That action is **entirely manual**.
- **VSS/snapshot rollback is greenfield.** Every VSS reference in the repo detects an
  *attacker* deleting shadow copies (the anti-recovery technique); none restores
  anything. `docs/detection/ransomware.md` says so: "VSS/snapshot integration is a later
  Windows item."
- **The damage manifest (#82) is server-side and ransomware-only.** The agent tracks
  `touched_files` per pid and attaches it to the triggering `Detection`; the server
  derives a durable `damageManifest` (files renamed or deleted, capped at 1000) from
  stored case events, exposed at `GET /api/cases/[id]`. It exists only for T1486 cases,
  it lives on the server, and it lists files the ransomware renamed or deleted — not
  files the agent quarantined, so nothing in it maps to a quarantine `sha256`.
- **There is no server-to-agent command channel.** Every response action fires either
  from the agent's own in-process verdict engine or from an operator with host access.
  `crates/transport`'s client exposes `get_json`/`get_bytes` and nothing that pushes a
  command the other way. The verdict model (#131, `crates/verdict`) is agent-local and
  ephemeral, and its only reversal primitive, `suppress`/`unsuppress`, silences *future*
  recordings; it does not undo a past action.

## Decision

Scope this ADR to **host-local, reversible remediation**: actions an operator with host
access triggers on the agent itself, the trust model response already uses. Two earlier
pieces of this ADR are taken out rather than half-designed (review of #133's ADR): the
damage-manifest batch restore and macOS launch-item remediation. Deleting persistence
artifacts is also out: v1 *disables* them, reversibly.

1. **Quarantine restore stays as it is: ungated.** An earlier draft gated it on a new
   policy flag. That was wrong: restoring a quarantined file is the same safe direction
   as lifting isolation, which ADR-0037 leaves ungated, and gating it would silently take
   the restore path away from every existing deployment on upgrade (default `false`).
   `agent quarantine restore` and `RESPONSE-UNQUARANTINE` are unchanged.

2. **Isolation lift**: a new `agent isolation lift` subcommand (same shape as `agent
   quarantine restore`) wires `lift_isolation` and emits `HOST-UNISOLATE`, the existing
   counterpart of `HOST-ISOLATE` in `crates/response/src/isolation.rs`. Ungated, per
   ADR-0037 §4. Ships once ADR-0037 is accepted and isolate-apply is wired into the
   binary; until then there is nothing live to lift.

3. **Persistence remediation: disable, never delete, and always undoable.**
   - **Its own policy flag.** `ResponsePolicy.persistence_remediation_enabled` (default
     `false`), separate from every other flag. It is the only destructive action this
     ADR adds, so it is the only one gated, and it does not share a switch with a
     restoring action.
   - **Bound to a detection.** `agent remediate <verb> <artifact> --alert <timestamp_ns>`
     names the `alerts.ndjson` line the operator is acting on (the same file `quarantine
     restore` already reads). It is refused unless that line exists, its technique is the
     verb's technique, and its message names this exact artifact: the rules already write
     `task=<name>` (T1053.005) and `service=<name>` (T1543.003), and the systemd and cron
     rules write the artifact's path. The command removes what a detection flagged, not an
     arbitrary name an operator typed.
   - **Strict input, no shell.** Every external command is spawned with an argv vector
     (`std::process::Command`), never through a shell. Names are validated against the
     platform's own grammar before use: a Windows service name against the SCM's rules
     (no `/` or `\`, at most 256 characters), a task name as a `\`-separated path with no
     `..` component, a systemd unit name with a known unit suffix. A path is canonicalized,
     must be a regular file directly inside an allowed root (below), and is opened without
     following symlinks (`O_NOFOLLOW`; on Windows, a reparse point is refused) so a link
     cannot redirect the action to another file.
   - **The verbs**, each with the OS step the earlier draft left out:
     - `scheduled-task <name>` (Windows, T1053.005): export the task's XML
       (`schtasks /Query /TN <name> /XML`) into the remediation archive, then
       `schtasks /Change /TN <name> /DISABLE`.
     - `service <name>` (Windows, T1543.003): record the start type, stop the service and
       **wait** for `SERVICE_STOPPED` and the process's exit (bounded, the same
       stop-and-wait ADR-0039 defines), then `sc config <name> start= disabled`. A stop
       that times out leaves the start type unchanged and reports failure.
     - `systemd-unit <name>` (Linux): `systemctl disable --now <name>`, then `systemctl
       daemon-reload`. The unit file stays where it is; the enablement symlinks are what
       `disable` removes, and the archive records which ones existed.
     - `cron <path>` (Linux, T1053.003): whole files directly in `/etc/cron.d/` only. The
       file is **moved** into the remediation archive, which both disables it and keeps
       it for undo. User crontabs (`/var/spool/cron`), single lines inside a file, and
       shell profiles are not covered (Deferred).
   - **Undo.** Every remediation writes a record into a remediation archive under the
     agent's state directory, created with the quarantine directory's own permissions
     (ADR-0021): an id, the verb, the artifact, what was there before (task XML, start
     type, enablement symlinks, the moved file), and the alert it acted on.
     `agent remediate undo <id>` puts it back: re-enable the task, restore the start type,
     `systemctl enable` the recorded symlinks then `daemon-reload`, move the cron file
     back (refusing to overwrite a file that has reappeared there). Undo is ungated, like
     every restoring action here.
   - **Audit.** One family, `RESPONSE-REMEDIATE` and `RESPONSE-REMEDIATE-UNDO`, in
     `alerts.ndjson` alongside the other `RESPONSE-*` lines, on success and failure
     alike. Fields: the verb's technique, the artifact, the archive id, the alert
     `timestamp_ns` it was bound to, the invoking user (uid or SID of the process token),
     and the outcome. A consumer filtering on `RESPONSE-` sees every response action;
     isolation keeps its own `HOST-*` family as ADR-0037 defined it.
   - **Where the code lives.** In the agent binary, `agent/src/remediate/{mod,windows,
     linux}.rs`, next to `agent/src/commands/{windows,linux,macos}.rs`, which already
     hold the binary's platform branches. Not in `crates/response`: that would need a
     second platform-code exception in a library crate, plus CLAUDE.md and
     `tools/check-deps.py` changes, for code only the binary calls. No dependency rule
     changes.

4. **VSS/snapshot rollback**: deferred outright. No placement decision is made here; a
   future ADR scopes the restore design and, with it, where Windows-only restore code
   can live.

## Consequences

**New**: `agent isolation lift` and `HOST-UNISOLATE` (once ADR-0037 lands);
`ResponsePolicy.persistence_remediation_enabled`; `agent remediate {scheduled-task,
service, systemd-unit, cron} <artifact> --alert <timestamp_ns>` and `agent remediate
undo <id>`; the remediation archive; `RESPONSE-REMEDIATE`/`RESPONSE-REMEDIATE-UNDO`;
`agent/src/remediate/`. ADR-0039's stop-and-wait routine gains a second caller.

**Unchanged**: `agent quarantine restore`, ungated as today.

**Unblocked**: issue #133's three bullets, as far as host-local action goes: file
restore (already built), isolation lift (wired, pending ADR-0037), persistence (disabled
reversibly, on Windows and Linux).

**Still not possible after this ships**: deleting a persistence artifact outright (the
operator still does that by hand, now with the artifact already disabled); macOS
launch-item remediation; remediation triggered from a console case decision; restoring
files a ransomware case's damage manifest lists; VSS rollback; automatic remediation.

**Depends on**: ADR-0037 (proposed) for isolation lift; ADR-0039 (proposed) for the
shared stop-and-wait, or the routine lands with whichever of the two ships first.

## Deferred

- **Deleting** persistence artifacts, rather than disabling them, once the archive has
  proven itself as an undo path.
- **macOS launch items** (`launchctl bootout`/`disable` need the right domain target:
  `system` for `/Library/LaunchDaemons`, `gui/<uid>` per user for LaunchAgents). That
  design belongs with the macOS sensor's owner.
- **Account removal** (T1136.001), user crontabs, single cron lines, and shell profiles.
- **Damage-manifest-scoped restore**: needs a server-to-agent channel to reach the
  manifest, and provenance from manifest entries to something restorable; neither
  exists.
- A server-to-agent command channel. Likely depends on #314/ADR-0040 for agent identity.
- VSS/Windows snapshot rollback, including where the platform-specific code would live.
- Automatic remediation triggered by a verdict rather than chosen by an operator.

## References

- #133 (this issue), #25 (response), #82 (ransomware pack / damage manifest), #131
  (verdict fusion, merged), #135 (console triage)
- ADR-0021 (quarantine permissions, accepted) — the archive reuses its directory posture
- ADR-0037 (host isolation, proposed) — `lift_isolation` and the `HOST-*` audit family
- ADR-0039 (Windows self-update, proposed) — the stop-and-wait routine the `service` verb
  reuses
- ADR-0040 (agent enrollment and mTLS, proposed) — the identity work a future command
  channel would likely need
- `docs/detection/ransomware.md`, `crates/rules/src/stateless.rs`,
  `crates/response/src/{quarantine,isolation}.rs`, `crates/policy/src/lib.rs`,
  `crates/verdict/src/lib.rs`, `agent/src/quarantine_cmd.rs`
