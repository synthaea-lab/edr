# ADR-0042: Response Remediation and Rollback

- **Status**: proposed
- **Date**: 2026-10-29

## Context

Response (issue #25) implements three containment actions — kill, quarantine, isolate —
and issue #133 asks for the recovery half: every destructive response reversible, and
attacker persistence removable, scoped to the case's damage, policy-gated and audited
exactly like response itself. That premise needs checking against what already exists,
because the three actions are not equally unowned:

- **Quarantine restore already exists, fully wired.** `unquarantine(quarantine_dir,
  sha256_hex)` (`crates/response/src/quarantine.rs:902`) restores a quarantined file to
  its original path, verifies the hash before returning it, restores the original Unix
  mode from the `.origin` sidecar, and never overwrites an occupied destination.
  `agent quarantine restore` (`agent/src/quarantine_cmd.rs`) wires it end to end, audited
  as `RESPONSE-UNQUARANTINE` into `alerts.ndjson` on both success and failure, with tests
  for the half-done-cleanup cases. The one real gap: unlike `quarantine_file` itself
  (gated on `ResponsePolicy.quarantine_enabled`), `unquarantine`'s CLI path is gated on
  nothing but host access — restoring a file is not "policy-gated... exactly like
  response," today it is operator-trusted and ungated.
- **Isolation lift is library-complete, with zero wiring.** `lift_isolation(firewall,
  intent_path, trigger, now_ns)` (`crates/response/src/isolation.rs:386`) exists, is
  fully tested, and is deliberately never policy-gated (ADR-0037 §4: lifting is the safe
  direction). But nothing outside `crates/response` calls it — no CLI command, no
  `HOST-UNISOLATE` audit line. This isn't a bug to fix; ADR-0037 is itself still
  **Status: proposed**, and its own text defers the binary-side wiring ("the firewall
  itself is injected by the binary", `crates/response/src/lib.rs:17`). Applying
  isolation isn't live in the shipped agent yet, so neither is lifting it.
- **Kill has, and needs, no undo.** Not a gap; out of scope by the issue's own framing.
- **Persistence removal has detection, not removal.** `crates/rules/src/stateless.rs`
  already names and detects scheduled tasks (T1053.005, `check_scheduled_task_persistence`,
  line 224), services (T1543.003, `check_service_install_persistence`, line 337), account
  creation (T1136.001, line 371), systemd units (line 405), macOS launch items (line 442),
  and the generic shell-profile/cron/LaunchAgents path family (T1546.004/T1053.003/
  T1543.002/T1037.004, line 126). Three of these rules' own doc comments state the alert
  exists so an analyst can act on it, and name the exact command: `schtasks /Delete /TN
  <name> /F` (line 221), `sc.exe delete <name>` (line 334), `net user <name> /delete`
  (line 368). Today that action is **entirely manual** — the project has already written
  down, in its own detection code, exactly what automated removal would need to run.
- **VSS/snapshot rollback is greenfield.** Every VSS reference in the repo
  (`stateless.rs:757`, `agent/src/sink.rs:4619`) detects an *attacker* deleting shadow
  copies (the anti-recovery technique); none restores anything.
  `docs/detection/ransomware.md:19` states plainly: "VSS/snapshot integration is a later
  Windows item." Restoring via VSS would be Windows-specific business logic, and per
  CLAUDE.md's platform-code rule, that fits none of the three existing exceptions
  (`crates/sensors/*`, `crates/updater`, quarantine's narrow ACL/descriptor boundary) —
  where it would even live is unresolved, not just unimplemented.
- **The damage manifest (#82) is real, durable, and ransomware-only.** The agent tracks
  `touched_files` per pid (64 pids × 100 events, counted shedding) and attaches it to the
  triggering `Detection`; the server derives a durable `damageManifest` (files,
  renamed/deleted, capped at 1000) from stored case events, exposed at
  `GET /api/cases/[id]`. But it exists **only for T1486 (ransomware) cases** — a kill or
  quarantine fired from any other verdict has no damage manifest to scope cleanup by.
  Issue #133's "scope every cleanup by the case's damage manifest" is true today only for
  that one case type.
- **There is no server-to-agent command channel.** Every response action that exists —
  kill, quarantine, isolate-apply — fires either from the agent's own in-process verdict
  engine, or from an operator with direct CLI/host access. `crates/transport::Client`
  exposes `get_json`/`get_bytes` and nothing that pushes a command the other way; no
  server route issues isolate/quarantine/remediate instructions to an agent. Issue #133's
  framing — "restore a file when a verdict is overturned" — implicitly assumes a path
  from a server-side case decision (#135, not yet built) back to the one agent that
  fired the original action. That path does not exist. The verdict model itself (#131,
  merged, `crates/verdict/src/lib.rs`) reinforces this: `VerdictEngine` is agent-local and
  ephemeral (a 16,384-entry `BoundedMap`, no case id, no durability), and its only
  reversal primitive, `suppress`/`unsuppress` (line 322), silences *future* technique
  recordings for an entity — it does not undo a past action. There is nothing to key a
  remote "the case was overturned, restore it" trigger on yet.

## Decision

Scope this ADR to **host-local remediation**: actions an operator with CLI/host access,
or the agent's own policy, can trigger on the agent itself — exactly the trust model
response already uses for kill/quarantine/isolate-apply. A console-driven remote trigger
needs a server-to-agent command channel that doesn't exist; building one is its own
cross-cutting decision (and likely depends on #314/ADR-0040's agent-identity work for
authenticating which agent gets to act on which host) and is explicitly not attempted
here.

1. **Quarantine restore**: close the one real gap rather than redesign. Add
   `ResponsePolicy.remediate_enabled: bool` (default `false`, same observe-only posture
   as `kill_enabled`/`quarantine_enabled`/`isolate_enabled`) and gate `agent quarantine
   restore` on it. `unquarantine` itself, its audit line (`RESPONSE-UNQUARANTINE`), and
   its tests are unchanged — this is a one-field, one-call-site addition.

2. **Isolation lift**: wire `lift_isolation` the way kill and quarantine are already
   wired — a new `agent isolation lift` subcommand (same shape as `agent quarantine
   restore`), emitting a new `HOST-UNISOLATE` audit line into `alerts.ndjson` (same shape
   as the existing `RESPONSE-ISOLATE`). Per ADR-0037 §4, this stays **ungated** —
   `remediate_enabled` does not cover it, matching "lifting is the safe direction."
   This piece ships once ADR-0037 itself (still proposed) is accepted and isolate-apply
   is actually wired into the binary; until then there's nothing live to lift.

3. **Persistence removal** — the new work this issue actually asks for. One `agent
   remediate <technique> <artifact>` subcommand family, operator-invoked like quarantine
   restore, each verb a thin wrapper around the platform command the existing detection
   rules' own doc comments already name:
   - `remediate scheduled-task <name>` → `schtasks /Delete /TN <name> /F` (Windows)
   - `remediate service <name>` → `sc.exe delete <name>` (Windows)
   - `remediate cron <path>` → remove the matched `/etc/cron.d/*` entry (Linux)
   - `remediate systemd-unit <name>` → `systemctl disable --now <name>` + unlink the unit
     file (Linux)
   - `remediate launch-item <path>` → `launchctl bootout` + unlink the plist (macOS)

   Gated on the same `ResponsePolicy.remediate_enabled` as quarantine restore — one flag
   for "I trust this agent to clean up," not a flag per technique. Audited as
   `RESPONSE-REMEDIATE-<TECHNIQUE>`, same actor/target/outcome shape as the existing
   `RESPONSE-*` lines. Each wrapper lands in new `crates/response` modules
   (`response::persistence::{scheduled_task,service,cron,systemd,launch_item}`),
   `#[cfg(target_os = ...)]`-gated per CLAUDE.md's platform-code rule. This is a second
   narrow platform exception inside `crates/response`, alongside quarantine's existing
   ACL/descriptor one (ADR-0021) — `tools/check-deps.py`'s comment and CLAUDE.md's
   platform-code section should say so explicitly rather than let it read as scope creep
   on the existing exception.

   Explicitly **not** attempted here: inferring *which* artifact to remove from a
   verdict automatically. The operator names the exact artifact (service name, task
   name, unit, path) from the alert they're looking at — mirroring how quarantine
   restore takes an exact sha256, not "restore whatever looked suspicious."

4. **Damage-manifest-scoped cleanup**: consumed only where a manifest exists. For a
   ransomware (T1486) case, `agent remediate` gains a batch form that reads the case's
   damage manifest and offers it as a restore candidate list (restore-by-manifest is a
   loop over the existing single-file `unquarantine`, not new restore logic). For every
   other case type, there is no manifest to scope by, and remediation stays one artifact
   at a time by operator choice. Generalizing #82's manifest to non-ransomware cases is
   not part of this decision.

5. **VSS/snapshot rollback**: deferred outright, same posture ADR-0015 took with macOS
   self-update. No placement decision is made here, because none can be made honestly
   yet — a future ADR scopes the actual restore design and, with it, decides where
   Windows-only restore code can live, since it fits none of today's three platform-code
   exceptions.

## Consequences

**New**: `ResponsePolicy.remediate_enabled`; `agent quarantine restore`'s policy gate;
`agent isolation lift`; `agent remediate <technique> <artifact>` and its manifest-batch
form; new `crates/response::persistence::*` platform-gated modules; `HOST-UNISOLATE` and
`RESPONSE-REMEDIATE-<TECHNIQUE>` audit events; a one-line addendum to
`tools/check-deps.py`/CLAUDE.md naming the second platform-code exception.

**Unblocked**: issue #133's three bullets — file restore (already built, now
policy-gated), isolation lift (wired, pending ADR-0037), persistence removal (new,
designed here).

**Still not possible after this ships**: remediation triggered remotely from a console
case decision (#135's triage UI can *display* the data this produces, but "click to
remediate" has no channel to travel on); VSS/snapshot rollback; damage-manifest scoping
for non-ransomware cases; any form of automatic (non-operator-chosen) remediation.

**Depends on**: ADR-0037 (proposed) for isolation lift to have anything live to act on.

## Deferred

- A server-to-agent command channel — without it, every remediation action in this ADR
  stays local-operator-triggered, never console-triggered. Likely depends on #314/
  ADR-0040 for agent identity.
- VSS/Windows snapshot rollback, including where the platform-specific code would live.
- Generalizing the #82 damage manifest beyond ransomware (T1486) cases.
- Automatic remediation triggered by a verdict rather than chosen by an operator.

## References

- #133 (this issue), #25 (response), #82 (ransomware pack / damage manifest), #131
  (verdict fusion, merged), #135 (console triage, not yet built)
- ADR-0021 (quarantine permissions, accepted) — the existing platform-code exception this
  extends
- ADR-0037 (host isolation, proposed) — `lift_isolation`'s existing design
- ADR-0040 (agent enrollment and mTLS, proposed) — the identity work a future command
  channel would likely need
- `docs/detection/ransomware.md`, `crates/rules/src/stateless.rs`,
  `crates/response/src/{quarantine,isolation}.rs`, `crates/policy/src/lib.rs`,
  `crates/verdict/src/lib.rs`
