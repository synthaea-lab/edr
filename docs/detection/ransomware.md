# Ransomware Protection Pack

A dedicated vertical over existing machinery — no new engine, one wired reflex:

1. **Canary tripwires** (`deception`): sentinel files in high-value directories;
   a write/rename/delete touching one is the earliest, cheapest encryption signal.
2. **Burst detection** (`rules`/`correlator`): mass rename/write patterns per pid
   within a short window + extension-churn and entropy-of-written-content features
   (T1486). Windows fidelity depends on delete/rename file events (audit F-6, #21).
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
