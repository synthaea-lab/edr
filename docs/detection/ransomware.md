# Ransomware Protection Pack

A dedicated vertical over existing machinery — no new engine, one wired reflex:

1. **Canary tripwires** (`deception`): sentinel files in high-value directories;
   a write/rename/delete touching one is the earliest, cheapest encryption signal.
2. **Burst detection** (`rules`/`correlator`): mass rename/write patterns per pid
   within a short window + extension-churn and entropy-of-written-content features
   (T1486). Windows fidelity depends on delete/rename file events (audit F-6, #21): the
   minifilter now sends them (#857, #853), and the rename rule counts them per pid. They
   carry only the pid (no `comm`, parent or user), so the per-parent shell-loop counter
   never sees them and a `comm`-gated exclusion fails closed. Pinned by
   `crates/rules/src/tests/ransomware_windows.rs`; not yet measured on a host (benign
   Windows producers of an appended-suffix rename are unknown).
3. **Reflex response** (`response` + policy): on a corroborated signal (canary +
   burst), kill the process tree and quarantine the binary — the one scenario where
   seconds matter enough to justify the most aggressive default policy ships with.
4. **Recovery posture**: the case records the damage manifest (files touched in the
   window) so restoration tooling has a scope; VSS/snapshot integration is a later
   Windows item.

   **Damage manifest (built, #82).** When a T1486 rule alert is recorded, the agent attaches
   the alerting process incarnation's recent renames and deletions to the detection as
   further events (`Detection::events` after the triggering one): the newest 100, oldest
   first, from a per-pid history in `rules::RuleState` (`touched_files`; 64 pids, 100 events
   each, counted shedding). No schema change. The control plane keeps the first event in the
   detection's `event` and the rest in `meta.additional_events`, and
   `GET /api/cases/[id]` returns `damageManifest: { files, truncated }`: the distinct files
   (renamed with their new path, or deleted) of the case's T1486 detections, oldest first,
   at most 1000. Not covered: files only *written* in place (a `FileWrite` has no path), and
   files touched before the history began (a process pushed out by 64 busier ones loses its
   manifest, not its detection).

   **Reflex (built, #82).** `agent/src/ransomware_join.rs` joins the two signals per process
   incarnation `(pid, process_generation)` in a sliding 60 s window of event time, in either
   order, bounded to 256 processes with counted shedding. A corroborated process goes to the
   policy-gated kill (`RESPONSE-KILL ... on a corroborated ransomware signal`); the Bayes gate
   and severity are untouched. Observe-only unless `--enable-kill`. Not built: killing the
   tree, quarantining the binary, and the lab acceptance run below.

   **Service-stop burst (built, #381).** `SERVICE-STOP-BURST` (T1489, Medium) alerts when one
   lineage stops five distinct services inside 60 s: `systemctl stop` / `disable --now` / `kill` (with a signal that ends the unit),
   `service X stop` and `/etc/init.d/X stop` (Linux), `net stop`, `sc stop`, `Stop-Service`
   (Windows), `launchctl bootout` / `unload` / `remove` / `stop` (macOS); an exec that names
   several services counts each, and a `Get-Service | Stop-Service` pipeline counts as one. It
   is the pre-encryption tell (databases, backup, mail and security services stopped so their
   files can be encrypted), and a maintenance window, a shutdown script or a package upgrade
   looks the same, hence Medium; five in a minute is a calibration choice, not a measurement.
   **It is still not joined to the damage manifest or the reflex:** both consume T1486
   alerts only, so a T1489 alert neither attaches files nor corroborates a kill. The one
   thing it feeds is the message of a later T1486 finding, see the next item.

   **Burst then mass renames (built, #973).** When a T1486 finding (any of its four sources)
   comes from the lineage that raised a SERVICE-STOP-BURST in the previous 15 minutes, its
   message ends with `corroborated: the lineage of pid=N stopped K distinct services
   (SERVICE-STOP-BURST, T1489) Ts earlier`. Nothing else changes: the technique, the
   severity (Critical already, so there is nothing to raise), the thresholds, the alert
   count, the damage manifest and the reflex are the same with or without the burst (tests
   `the_corroboration_changes_neither_...`, `a_burst_does_not_lower_the_rename_threshold`).
   The lineage of a rename is the one its process was exec'd under (the shell that launched
   the encryptor, or the loop shell of the `mv` shape) or the process itself. A process that
   started before the agent has no recorded lineage and gets no note. The memory is one
   mark per lineage (16384, least recently used evicted), refreshed while the burst goes on,
   read at the finding and never consulted for anything but the message.

   **Shutdown or reboot as case context (T1529, built, #973).** Low, and never on its own:
   `shutdown`, `reboot`, `halt`, `poweroff`, `systemctl reboot|poweroff|halt|kexec|soft-reboot`,
   `init|telinit 0|6` and `shutdown /s|/r|/p` are reported only when the same lineage
   (the shell, or the encryptor as the parent of the command) raised a **T1486 or T1490**
   finding in the previous 30 minutes, once per finding. The note says the command was
   seen, not that the host went down. Without such a finding the exec records nothing and
   raises nothing. A SERVICE-STOP-BURST alone does not arm it: stop five services then reboot
   is the patch window. Low means the verdict, which takes the maximum severity over an
   entity, cannot rise because of the note; it adds a technique to the case. The program name
   is enough for `shutdown`, `reboot`, `halt` and `poweroff` (the argv of a short-lived process
   can be empty, ADR-0045), the others need their arguments and are missed without them
   (fail closed). A visible `-c`, `-k`, `--cancel`, `--help`, `--dry-run`, `reboot -w` or
   `shutdown /a` is not a shutdown. Not built: a shutdown *before* the finding (it would have
   to edit a finding already sent), the manager's journal record as the source
   (ADR-0006, needs a new event), and Windows/macOS-specific forms beyond the ones above.
   Decisions and what is not verified: `issues/issue-973.md`.

   **Not built, on purpose (#973):** the sudo-burst threshold (no measurement to calibrate
   it), the Windows failed-then-success join (4672 and 4624 are routine for administrators),
   and T1486 on Windows and macOS telemetry (waits on #853 and #857; macOS Endpoint Security
   has no `FileWrite`).

Acceptance is scenario-driven: a lab encryptor (benign, marker-based) must be killed
before it processes more than N canary-adjacent files.

## File Activity Detection (issue #262)

With `FileWrite`, `FileDelete`, and `FileRename` telemetry (SCHEMA_VERSION 15+),
the burst detection component (#2 above) now has real-time syscall-level signals:

- **Mass rename patterns**: detect `.locked`/`.encrypted` suffix in 50+ files/60s
- **Burst write + rename correlation**: 100MB written + 50 renames in 60s window
- **FileOpen → FileWrite correlation**: `FileWriteEvent` has no path, rules must join
  to prior `FileOpenEvent` on `(pid, fd)` to get file paths

See **[file-activity-patterns.md](./file-activity-patterns.md)** for:
- Full detection pseudo-code with thresholds
- Correlation patterns and state management
- False positive mitigation strategies
- Performance considerations (write syscalls are high-volume)
