# ADR-0029: Canary placement and how the agent raises a canary hit

- **Status**: proposed
- **Date**: 2026-10-07

## Context

`crates/deception` (issue #81, slice 1) plans, plants and matches canary files, but nothing
in the agent used it. Wiring it raises three questions the crate cannot answer: where
canaries go, where the per-install seed lives, and how a hit is reported without changing
the semi-frozen `schema`.

## Decision

1. **Placement is opt-in.** `[deception] canary_dirs = [...]` in `agent.toml` (ADR-0013)
   lists absolute, existing directories (at most 16, no duplicates, validated at load).
   An absent table plants nothing: a decoy belongs where nothing legitimate reads it, and
   only the operator knows which directories those are on a given host. Each directory gets
   one canary per kind. Directories are never created.
2. **The seed is generated once** from the OS random source and kept in
   `<state_dir>/deception/seed` (owner-only on Unix), next to `inventory.json`. A seed file
   of the wrong length disables planting instead of being regenerated, because a new seed
   would rename the canaries and orphan the planted ones.
3. **Removing the table removes the canaries.** With no directories configured, the agent
   deletes what the inventory lists at start. That is the uninstall path for the decoys
   (see 7 for when that can happen).
4. **A hit is a `Rule` detection**, `rule_id = "DECEPTION-CANARY"`, severity High, technique
   T1083, with the triggering event attached. No new `DetectionSource` variant: that is a
   schema change (fixtures, version bump) and is deferred until the server needs to
   distinguish deception findings structurally (decoy-credential alarms will).
5. **The agent's own pid never raises a hit**; it writes the canaries at start.
   A process that touches the same canary again within 60 s (event time) raises no second
   detection (a `grep -r` opens every canary many times); absorbed touches are counted and
   the table is bounded at 1024 `(canary, pid)` pairs.
6. **Planting failures degrade, one directory at a time.** Canaries are planned once for
   every directory (so names differ) and planted per directory: a directory the agent
   cannot write costs its own canaries, logs why, and the rest are planted and watched.
   With none writable the agent runs without tripwires.
7. **Dropping the table removes the canaries, and only a successfully loaded config can
   drop it.** `config::load` fails fast on a missing or invalid file (ADR-0013) and the
   agent exits; there is no fallback to defaults, so a broken `agent.toml` cannot
   silently remove the canaries. Only a valid file without `[deception]` does.

## Consequences

- A host running the agent outside the packaged unit turns the feature on with one config
  line, and off by deleting it. **With the packaged unit it takes two steps**:
  `ProtectSystem=strict` makes everything outside `ReadWritePaths` read-only to the
  unprivileged `synthaea` user, so a `canary_dirs` entry under `/home`, `/srv` or `/var/www`
  fails to plant until a drop-in adds it to `ReadWritePaths` and the directory is writable by
  that user. `docs/operations/deception.md` gives the drop-in; without it the log says
  "planting failed here" for that directory.
- Known gaps, from the slice 1 review, that decide whether the tripwire fires in the field:
  - The Linux sensor reports `openat` paths as passed, so a relative open
    (`cd dir && cat name`) does not match an inventoried absolute path.
  - Read-only opens under `/tmp`, `/var/tmp` and `/dev/shm` are filtered by the sensor, so
    canaries placed there never fire on a read.
  - Known indexers and backup agents will touch canaries; there is no allow-list yet.
- Decoy credentials, honeypot listeners and the refresh policy are still to come.
