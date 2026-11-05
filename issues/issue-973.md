# Issue #973: Impact context, T1529 and the service-stop corroboration

**Branch:** `feat/973-impact-context` (from `main` 793c5ad3) · **Status:** the two OS-neutral items are built, no VM and no real telemetry used. Windows/macOS T1486 and the T1548 remainder stay deferred.

## What was built
- **Corroboration** (`crates/rules/src/impactctx.rs`, `RuleState::note_t1486`): a T1486 finding from the lineage that raised SERVICE-STOP-BURST in the previous 15 minutes says so in its message.
- **T1529 as context** (`RuleState::check_shutdown_context`): a shutdown or reboot command from a lineage that raised a T1486 or T1490 finding in the previous 30 minutes is reported Low, once per finding. Never raised without that finding.
- Tests: `crates/rules/src/tests/impact_context.rs` (24). `tools/attack-coverage.py` maps T1529 to Impact; `docs/detection/attack-coverage.md` regenerated.

## Not built, as the issue says
- The sudo-burst threshold: configuration management, install scripts and CI do many sudo successes, and there is no measurement to calibrate against.
- The Windows failed-then-success join (4672 and 4624 are routine for administrators).
- T1486 on Windows and macOS telemetry: waits on #853 and #857; macOS Endpoint Security has no `FileWrite`. No test yet puts a Windows or macOS path shape through the rename rule; add one when they merge.
- The setuid-binary half of T1548 (joins #266's telemetry).

## Decisions taken under delegation
Each is a choice made without the owner. Revisit any of them freely.

1. **The corroboration is a message note, not a severity change.** Why: T1486 is already Critical, so there is nothing to raise; and the manifest and the reflex read the technique and the event, so a text suffix cannot move what feeds them. The boundary of #381 is kept and pinned by tests (same technique, severity, alert count, touched files; threshold not lowered). Not verified: that no consumer outside this repo's agent and server parses the message text (nothing in `agent/` or `verdict` does; the control plane was not read).
2. **Window 15 minutes, burst to rename.** Why: a scripted run renames within seconds to minutes of stopping services, a hands-on one may take longer; the mark is refreshed while the burst continues. A guess, not a measurement. Not verified: any real run.
3. **Applied to all four T1486 sources** (appended-suffix rename per pid and per ppid, write volume, write-new-then-unlink), at the `on_file_rename` / `on_file_delete` level rather than only in `check_mass_rename_pattern`, so one rule governs the note. The issue named the rename rule; the others are the same finding.
4. **"Same lineage" = `recon::Lineage`** (the parent whose children are counted together, with one-shot shell wrappers resolved), plus the renaming process itself as a lineage (an encryptor that runs `reboot` as its own child). Not verified: a process that daemonises or double-forks away from the shell loses the link; a process started before the agent has no lineage and gets no note.
5. **State is bounded like the other lineage rules:** two `BoundedMap`s of `COUNTER_CAP` (16384) entries, LRU, one small value per lineage, expiry checked on read against event time. Tests show an evicted lineage is forgotten.
6. **T1529 attaches by being emitted Low, only after a finding.** The alternative (editing the earlier finding) is impossible: it is already sent and spooled. Why Low: the verdict takes the maximum severity per entity, so the note cannot raise a verdict; it adds a technique to the case. Why only after: a reboot after encryption or recovery destruction is the finish of the run; before, we would have to hold the reboot and attach it later. Not built: reboot before the finding. Not verified: how the control plane groups this detection into the case of the T1486 one (it is emitted under the shutdown process's entity, not the encryptor's); the lineage link is in the message text only.
7. **Armed by T1486 and T1490 only, not by SERVICE-STOP-BURST.** Stopping services then rebooting is the normal patch window; arming on it would put a note on routine maintenance. Package managers, cloud agents and an admin's `systemctl reboot` are other lineages in practice, and never reach a finding. Residual false positive: an administrator who triggers a T1486 false positive and reboots from the same shell gets a Low note on a case that already exists.
8. **The command is read from the program name, not from the argv, where the name is enough** (`shutdown`, `reboot`, `halt`, `poweroff`), because argv can be empty for short-lived processes (ADR-0045, #1118). `systemctl reboot` and `init 6` need their arguments and are missed when empty (fail closed). A visible cancel, dry run, help or wtmp-only flag excludes the command. Not verified: that real argv is present or empty on these commands on a VM; `shutdown -c` bypass classes like those #1109 found for the host-stop condition are possible (a missed exclusion only adds a Low note to an existing case, so the cost is bounded).
9. **No journal source, no schema change.** ADR-0006 says the manager's `reboot.target` record is the right source of "the host is going down". On `main` the journal sensor only emits security-tool unit stops (`FLAG_UNIT_STOPPED`, being replaced by a `UnitStop` variant in #1102/ADR-0012, which claims schema 62). Using it needs a new event and a schema version, and 60, 61 and 62 are claimed by unmerged #1114, #1116 and #1127. So none was added; the note says the command was seen, never that the host stopped. Revisit when the journal event exists: replace the exec test with it.
10. **Dispatch cost:** `check_recovery_inhibit` now runs a second time per exec inside `RuleState::on_exec` (once in `evaluate_exec`) to arm T1490, so that this state does not depend on the stateless call. Cheap (a lowercase and a few `contains`); not measured.

## Not verified
No VM, no real telemetry: every behaviour above is unit-tested on synthetic events only. Not run: a real ransomware-shaped run, a real `systemctl reboot` after one, the control plane's case grouping, the false-positive rate of either item on a fleet.
