# Issue #1036: Defense Evasion on Linux, T1070.006 timestomp and T1562.001 beyond command lines

**Branch:** `feat/1036-linux-timestomp` · **Sensor issue:** #1044 · **Status:** partial, draft PR

## Decisions (user, 2026-10-29)
- Capture with the BPF-LSM `inode_setattr` hook, not the `utimensat` tracepoints.
- Reuse `schema::FileSetTimeEvent` (Unix times converted to `FILETIME` units): no schema bump, one rule for both OSes.

## Done (verified on the host)
- `sensor-linux-wire` v27: `FileSetTimeEvent` (raw `timespec64`, flags for which of atime/mtime the caller chose); the version assert in `sensor-linux` and `sensor-linux-uprobes` follows.
- `sensor-linux` `normalize::file_set_time`: only the chosen fields are `Some`; conversion saturates and never yields 0/-1/-2 (the rule's "unchanged" values). 2 tests.
- `rules::evaluate_file_set_time` on Linux: `comm` printed, package managers (exact `comm`) skipped, everything else stays Low. 4 tests (positive, package managers, look-alikes, no chosen time).

## Not done
- **The eBPF hook** (`inode_setattr`, reading `struct iattr`/`dentry` through BTF offsets, path rebuilt from the dentry chain) and the userspace ring-buffer drain for it: tracked in #1044. Cannot be built or loaded on the dev host (no `bpf-linker`); needs the lab VM. Until then nothing emits the event on Linux.
- **Lab verification:** none run. The VMs were started by another session for other work.
- **Benign `touch` by a build tool:** indistinguishable from a stomp without the parent or a per-process count; stays Low.
- **T1562.001 beyond command lines:** stays open. No unit-lifecycle event source exists (the journal source emits ssh, pam and sudo; #362 covers only the agent's own pid). Candidates to name in a follow-up: a `systemd` unit-state journal source, or the `kill` signal path (`SignalEvent`, #362) widened beyond the agent's pid.
