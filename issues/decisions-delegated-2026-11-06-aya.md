# Decisions taken under delegation: the aya family bump (2026-11-06)

Context: dependabot opened #1154 (`aya-obj` 0.3 to 0.6) and #1156 (`aya-log` 0.3 to 0.4) as separate
PRs. Each left two versions of the `aya` family in the lockfile and failed CI (`E0308` in
`sensor-linux-lsm`). The family has to move together.

| Decision | Choice | Why |
|---|---|---|
| One PR for the family | `aya` 0.14 to 0.16, `aya-obj` 0.3 to 0.6, `aya-log` 0.3 to 0.4, `aya-ebpf` 0.2.1 to 0.3, `aya-log-ebpf` 0.2.0 to 0.3 | The userspace `aya-log` 0.4 reads the wire format of `aya-log-common` 0.3, which only `aya-log-ebpf` 0.3 writes. Leaving the probe side on 0.2 would compile and then mis-decode the probes' log lines. The lockfile now holds a single `aya-log-common`. |
| #1154 and #1156 | Closed in favour of this PR | Neither can merge alone. |
| `UProbe::attach` | `[symbol.offset]` | aya 0.16 takes a list of points; a `u64` converts to `UProbeAttachLocation::AbsoluteOffset`, the same meaning as before. |
| Map setters | Pass `&key` / `&value` | aya 0.16 takes references. No behaviour change. |
| Where the probes are verified | The `linux-ebpf` CI job, not a local build | The job has the pinned nightly and a prebuilt `bpf-linker`; this machine has neither. |

## Not verified

- **The probes were not built or loaded** by me. `bpf-linker` is absent here, so `cargo check` skipped the
  embedded probes ("building WITHOUT embedded eBPF probes"). The `linux-ebpf` job is the first build of
  `aya-ebpf` 0.3 / `aya-log-ebpf` 0.3 against the pinned nightly (`ebpf-toolchain.txt`).
- **No lab VM was used.** Whether the agent still loads its probes and attaches the uprobes on a real kernel
  is not measured. A run on the Fedora lab VM is still due before a release.
- **Tests were built (`--no-run`), not run**, because the Linux test runner needs sudo.
- The aya 0.16 and aya-ebpf 0.3 changelogs were not read; only the compiler errors guided the fixes.
