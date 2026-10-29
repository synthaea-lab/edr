# Issue #1036: Defense Evasion on Linux, T1070.006 timestomp and T1562.001 beyond command lines

**Branch:** `feat/1036-linux-timestomp` · **Sensor issue:** #1044 · **Status:** T1070.006 done and verified in the lab; T1562.001 stays open

## Decisions (user, 2026-10-29)
- Capture with the BPF-LSM `inode_setattr` hook, not the `utimensat` tracepoints.
- Reuse `schema::FileSetTimeEvent` (Unix times converted to `FILETIME` units): no schema bump, one rule for both OSes.

## Done (verified on the host)
- `sensor-linux-wire` v27: `FileSetTimeEvent` (raw `timespec64`, flags for which of atime/mtime the caller chose); the version assert in `sensor-linux` and `sensor-linux-uprobes` follows.
- `sensor-linux` `normalize::file_set_time`: only the chosen fields are `Some`; conversion saturates and never yields 0/-1/-2 (the rule's "unchanged" values). 2 tests.
- `rules::evaluate_file_set_time` on Linux: `comm` printed, package managers (exact `comm`) skipped, everything else stays Low. 4 tests (positive, package managers, look-alikes, no chosen time).

## Done in the lab (2026-10-29, #1044)
`edr-lab-fedora` (Fedora 43, kernel 7.2.9, `bpf` in the active `lsm=`), snapshot `test-1044-20261029-1` over `edr-ready-3` taken with the VM off, agent built offline from this branch (`~/edr-1044`; the new `ort` prebuilt had to be copied from the host cache, the VM has no Internet). `inode_setattr` loaded and attached on the first try. Scenario `lab/scenarios/timestomp-linux.sh` (captures in `lab/captures/test-1044-20261029/`): exactly 3 T1070.006 alerts with the full path (`touch -d`, python `os.utime`, `touch -m -d`); the write, the plain `touch` and the `chmod` raised nothing. Limits measured: a chain of more than 8 names reports the last 8 behind `/...`; a name over 31 bytes is cut; `/tmp` (tmpfs) reports `/lab1044-roottmp`, i.e. no mount point. Not run: a package-manager unpack (the skip is unit-tested only), `io_uring`, `--enable-kill`. Test snapshot deleted without revert; the VM keeps `~/edr-1044` and `~/lab1044`.

## Done earlier, on the host
(see below)

## Not done
- **Mount point in the path**, and names over 31 bytes: see the limits above. Resolving the mount needs `struct vfsmount`/`mount` offsets (not a `dentry` field) or a userspace lookup; not attempted.
- **Benign `touch` by a build tool:** indistinguishable from a stomp without the parent or a per-process count; stays Low.
- **T1562.001 beyond command lines:** stays open. No unit-lifecycle event source exists (the journal source emits ssh, pam and sudo; #362 covers only the agent's own pid). Candidates to name in a follow-up: a `systemd` unit-state journal source, or the `kill` signal path (`SignalEvent`, #362) widened beyond the agent's pid.
