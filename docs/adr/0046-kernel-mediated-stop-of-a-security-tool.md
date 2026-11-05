# ADR-0046: Kernel-mediated stops of a security tool: what is read from the command, what waits for a probe

- **Status**: proposed
- **Date**: 2026-11-05

## Context

#1138 (follow-up of #1103, PR #1114): a security tool can be ended or frozen by the kernel without
a signal the `signal_generate` probe reports. `prlimit --cpu=1:1 --pid <tool>` (the next CPU tick
sends `SIGKILL` as `SEND_SIG_PRIV` to the tool itself), a low `memory.max` (the memcg OOM kill is
`SEND_SIG_PRIV` too) and `cgroup.freeze` (no signal, same effect as `SIGSTOP`). Read from kernel
v6.12 source only. No VM was touched for this change.

What the sensor sees today: the exec stream (argv, ADR-0045 pending), `FileOpenEvent`. The open
probe drops every `/sys/` path before the ring buffer (`wire::path_filter::is_filtered_path`), so
a write to a cgroup control file is invisible. There is no `prlimit64` probe and no pid-to-tool map
in the rules.

## Decision

1. **Exec rule, built** (`check_security_tool_throttle`): `systemctl freeze <tool>` and
   `systemctl set-property <tool> MemoryMax|MemoryHigh|TasksMax=<limit>` (not `infinity`), Medium
   like the stop verbs. These two are the supported way to do it and go through pid 1, so the
   cgroup write is pid 1's.
2. **`prlimit --pid N --cpu|--as=<limit>`, built, Low**: the exec names a pid, not a tool; the
   alert says so and attributes nothing. Raising it to Medium needs the syscall-level event and a
   watched-tgid check, which is the sensor-side work below.
3. **Direct cgroup write rule, built but fed by nothing** (`check_security_tool_cgroup_write`): a
   write-intent open of a throttle file under `/sys/fs/cgroup/**/<listed>.service/`, pid 1
   skipped. It is the contract of the probe change; it is tested with synthetic events only.
4. **Probe changes, not made, need a VM**: (a) let write-intent opens under `/sys/fs/cgroup/` through
   `is_filtered_path` (the `/tmp/` pattern). Open questions only a lab answers: volume (systemd and
   container runtimes write `cgroup.procs` and limits constantly; a suffix filter in the probe is a
   loop or a memcmp the 5.15 verifier may reject, see the file's own history), and that the 14 file
   programs still load. (b) a `sys_enter_prlimit64` tracepoint reporting `RLIMIT_CPU`/`RLIMIT_AS`
   with a non-trivial new limit and the target tgid, matched against the watched pid map like
   `is_watched_signal_target`.
5. **No schema change.** The rules reuse `ExecEvent` and `FileOpenEvent`. (b) would need a new
   event or a field: it takes a schema version (60, 61 and 62 are claimed by #1114, #1116, #1127)
   and is deferred.

## Consequences

- Covered by command line: the two `systemctl` verbs and a `prlimit` that names a pid. Bypasses:
  `echo > memory.max`, `prlimit` called by a program (`setrlimit`/`prlimit64` from Python or C),
  abbreviations and clustered short options, an empty `argv` (#1118).
- The cgroup-file rule has no producer until 4a lands. Documented in
  `docs/detection/security-tool-stop.md`; not claimed as detection.
- Needs a VM to reproduce first, per the issue's "done when": the three kernel paths themselves, the
  exact open flags of `echo > memory.max` (the rule accepts `O_WRONLY`, `O_RDWR`, `O_TRUNC`), the
  cgroup path seen from the probe, whether `systemctl set-property` shows pid 1 as the writer.
