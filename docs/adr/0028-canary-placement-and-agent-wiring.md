# ADR-0028: Canary placement and how the agent raises a canary hit

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
   deletes what the inventory lists at start. That is the uninstall path for the decoys.
4. **A hit is a `Rule` detection**, `rule_id = "DECEPTION-CANARY"`, severity High, technique
   T1083, with the triggering event attached. No new `DetectionSource` variant: that is a
   schema change (fixtures, version bump) and is deferred until the server needs to
   distinguish deception findings structurally (decoy-credential alarms will).
5. **The agent's own pid never raises a hit**; it writes the canaries at start.
6. Planting failures degrade: the agent runs without tripwires and logs why.

## Consequences

- A lab can turn the feature on with one config line, and off by deleting it.
- Known gaps, from the slice 1 review, that decide whether the tripwire fires in the field:
  - The Linux sensor reports `openat` paths as passed, so a relative open
    (`cd dir && cat name`) does not match an inventoried absolute path.
  - Read-only opens under `/tmp`, `/var/tmp` and `/dev/shm` are filtered by the sensor, so
    canaries placed there never fire on a read.
  - Known indexers and backup agents will touch canaries; there is no allow-list yet.
  - Repeated opens raise one detection each; there is no per-canary cooldown yet.
- Decoy credentials, honeypot listeners and the refresh policy are still to come.
