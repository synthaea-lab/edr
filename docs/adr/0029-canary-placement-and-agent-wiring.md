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
   A process that *reads* the same canary again within 60 s (event time) raises no second
   detection (a `grep -r` opens every canary many times); absorbed touches are counted and
   the table is bounded at 1024 `(canary, pid, process incarnation)` triples, so a reused
   pid is not absorbed as its predecessor. A delete, a rename or a write-intent open is
   never absorbed: it is the destructive touch an encryptor makes after reading, and it is
   bounded by the number of canaries.
6. **Planting failures degrade, one directory at a time.** Canaries are planned once for
   every directory (so names differ) and planted per directory: a directory the agent
   cannot write costs its own canaries, logs why, and the rest are planted and watched.
   With none writable the agent runs without tripwires.
7. **Dropping the table removes the canaries, and only a successfully loaded config can
   drop it.** `config::load` fails fast on a missing or invalid file (ADR-0013) and the
   agent exits; there is no fallback to defaults, so a broken `agent.toml` cannot
   silently remove the canaries. Only a valid file without `[deception]` does.
8. **Known readers are allowed by executable, not by name.** `[deception] allow_exe`
   lists absolute paths (at most 32). A touch is allowed only when `/proc/<pid>/exe` of the
   toucher equals an entry that sits in a trusted system location
   (`policy::name_exclusion_applies`); a `comm` match would let any process rename itself
   past the tripwire. Unlike the exclusions that keep an unknown path, this **fails
   closed**: a process that exited before the lookup, a replaced binary (`... (deleted)`)
   and every non-Linux platform raise the hit. The lookup runs only on a hit, never per event.
   Further limits of the list, from the review of #699:
   - **Same mount namespace only.** A process in a container or chroot reports a path in its
     own view, so its `/usr/bin/updatedb` would equal the host's; it is not resolved and
     raises the hit (the agent's `/proc/<pid>/ns/mnt` is compared with the process's).
   - **No shells or interpreters.** A name such as `bash`, `python3.x`, `perl`, `find` or
     `env` is rejected at load: allowing it would exempt every script it runs. The list is a
     guard against the obvious mistake, not a complete one.
   - **Entries are canonicalised** when the agent starts, because `/proc/<pid>/exe` reports the
     real file (`/usr/bin/updatedb` is `updatedb.plocate` on Debian; usrmerge makes `/bin/x`
     `/usr/bin/x`). An entry that does not resolve is kept as written.
   - **"Trusted system location" is a heuristic** (`policy`): `/usr/` and `/opt/` qualify, and
     `/opt/<app>/` is often owned by the application's own user. Do not list a binary an
     unprivileged user can replace.
   - **Another user's process needs ptrace access.** Reading `/proc/<pid>/exe` and `ns/mnt` of
     a process of another user needs `CAP_SYS_PTRACE`, which the packaged unit does not grant
     (see its capability notes). Without it nothing resolves for such a process, and a root
     indexer such as `updatedb` still raises the hit.
   - **Pid reuse** between the event and the `/proc` read, by an allowed process, is a very
     narrow window that is not closed.

9. **The refresh policy: a deleted canary is planted again, and only that.** At each start,
   and every hour while the agent runs (a detached thread), a canary that is inventoried and
   whose file is gone is recreated with the content it had (`deception::refresh`). A file that
   is present is never touched, whatever it holds (modified or replaced content is counted and
   logged, `verify` says how); a canary the inventory does not know is not planted by it; a
   path taken by a symlink or a directory is left alone; and content the plan no longer
   produces (a newer build) is not restored under the old hash. The deletion was itself a
   tripwire hit, so restoring the decoy hides nothing; the agent's own re-creation is ignored
   like its other writes. An operator who wants a decoy gone removes the `[deception]`
   entry, not the file.

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
    canaries placed there never fire on a read (they still fire on delete, rename and a
    write-intent open). The agent warns at start for each such directory, using the sensor's
    own `is_filtered_path` so the check cannot drift; it still plants them.
- Decoy credentials are ADR-0030; honeypot listeners are still to come.
