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
   event or a field: it takes a schema version (the next free one when it lands: each schema PR takes the number after `main`'s at merge time)
   and is deferred.

## Consequences

- Covered by command line: the two `systemctl` verbs and a `prlimit` that names a pid. Bypasses:
  `echo > memory.max`, `prlimit` called by a program (`setrlimit`/`prlimit64` from Python or C),
  clustered short options, an empty `argv` (#1118), **an ancestor slice** (`systemctl freeze
  system.slice`, `set-property system.slice MemoryMax=...`, a write to
  `system.slice/cgroup.freeze`), **moving the tool's pid into a cgroup the attacker froze or
  limited** (`cgroup.procs`; #1114's moved-out tracking keeps watching the pid, but no signal comes
  from a freeze), a bare relative file name (`cd` into the unit's directory, then `echo 1 >
  cgroup.freeze`: the event has no working directory), and `..` in a path. `CPUQuota` is left out
  too: a quota low enough to blind a tool that must keep up with a ring buffer is a threshold
  judgement this rule cannot make without parsing the value, and ordinary tuning looks the same.
- The cgroup-file rule has no producer for the canonical `/sys/fs/cgroup/...` path until 4a
  lands: `is_filtered_path` drops a path that *starts with* `/sys/`. A relative path, `//sys/...`
  and `/./` or `//` inside the path pass the filter and the rule reads them (SoFrexs's review of
  #1145; read in the filter and the normalizer, **not measured on a VM** that these opens leave the
  probe). Documented in
  `docs/detection/security-tool-stop.md`; not claimed as detection.
- Needs a VM to reproduce first, per the issue's "done when": the three kernel paths themselves, the
  exact open flags of `echo > memory.max` (the rule accepts `O_WRONLY`, `O_RDWR`, `O_TRUNC`), the
  cgroup path seen from the probe, whether `systemctl set-property` shows pid 1 as the writer.

## Lab measurement (2026-11-05, Fedora 43, kernel 7.2.9)

Run on the lab VM with an existing agent build (`agent-1127`, content of `edr-1103`, so **without** the
#1138 rules), observe-only, a synthetic `osqueryd.service` (a copy of `sleep`). What the agent saw,
from `events.ndjson` (capture kept outside git, `lab/captures/test-1138-20261105/`):

- **No `file_open` for any `/sys/fs/cgroup/` path, from any process.** Not for `echo 400M >
  memory.max` (sh), not for a python `open(memory.high, 'w')`, not for the `cgroup.freeze` write, not
  for pid 1 on `systemctl set-property` or `freeze`. Zero events contain `/sys/fs/cgroup`; the only
  `/sys` open is a directory open by pid 1. The control (`echo x > /tmp/ctl-1138` by sh) did produce
  `file_open` with flags 577 (`O_WRONLY|O_CREAT|O_TRUNC`). So the cgroup-file rule (item 3) has no
  producer, as designed, and 4a is confirmed necessary. The open flags of `echo > memory.max`
  therefore remain **unmeasured** (the event never exists).
- A `file_write` event does exist for those writes (`fd`, `bytes_requested`, no path): sh fd 1, 5
  bytes for `400M\n`; python fd 3, 5 bytes. It cannot identify a cgroup file.
- `systemctl set-property osqueryd MemoryMax=500M`: pid 1 (comm `systemd`, ppid 0) opened
  `/etc/systemd/system.control/osqueryd.service.d/.#50-MemoryMax.conf...` (flags 524738) and
  `/etc/systemd/system.control`. So pid 1 is the actor, and its drop-in write is visible, but as an
  `/etc/` open, not a `/sys/` one. No `/sys/` open by pid 1. This is a possible extra signal
  (a `50-Memory*.conf` or `50-Tasks*.conf` under `system.control/<tool>.service.d/`), not built.
- **argv is the weak point of the exec rules**: the argv read failed (empty `argv`, empty `cmdline`)
  for 5 of 8 `systemctl` execs and for 3 of 3 `prlimit` execs, including `freeze`, `thaw` and both
  `prlimit --pid 1196` runs; `set-property` had its argv. Across the run most short-lived
  execs had none (`cat` 44 of 47, `grep` 49 of 63, `find` 32 of 40). With an empty argv
  `check_security_tool_throttle` cannot match, so on this agent build the two `systemctl` verbs
  and `prlimit` were mostly **not seen by command line**. This is the race named in ADR-0045 (#1118);
  whether the probe-side capture removes it for these execs is not measured here.
- `exec` events also show `image_path` as `/usr/sbin/<name>` for `/usr/bin` tools (symlink resolved);
  nothing in the rules compares on the directory.
- **No unit-stop event and no signal event** for freeze, set-property, direct writes, `prlimit` or
  the OOM kill. `signal` events seen are only `systemd-journal` signal 0 to the agent. `unit_stop`
  (pid 1, comm `osqueryd.service`) appears only for the plain `systemctl stop`, which the existing
  stop rule alerted on (T1562.001, "stopped the security tool osqueryd").
- OOM kill: a unit `osqueryd-oom.service` (`MemoryMax=30M`, python hog) was killed by the kernel
  (`Result: oom-kill`, journal `Memory cgroup out of memory: Killed process`). The agent saw the hog's
  exec and nothing about its death: no signal, no unit_stop. The same unit `systemctl status` says
  `signal=KILL`, but no `signal_generate` event exists for it.

Not measured: the #1138 rules themselves on a VM (the agent build predates them); a real OOM or
`RLIMIT_CPU` kill of the main process of the tool unit (the synthetic main process `sleep` uses no CPU,
the OOM hit a sibling unit); `systemctl set-property --runtime` (`/run/systemd/system.control`); cgroup v1
files; the probe change 4a and its verifier/volume cost; the `prlimit64` tracepoint. Disk 49 % used at
start, clock fixed, one run, one VM not otherwise loaded.

## Decisions taken under delegation (2026-11-05)

The owner left the open points to the session that built this change. What was decided, and why, so a reviewer can overrule it:

| Point | Decision | Why | Not verified |
| --- | --- | --- | --- |
| Probe change (let write-intent `/sys/fs/cgroup/` opens through `is_filtered_path`) | **Not made here.** | The filter is inlined in 14 BPF programs; the verifier on 5.15 and the ring volume cannot be judged without a run on each kernel, and the lab run of 2026-11-05 shows the rule would still miss the `systemctl set-property` path (pid 1 writes an `/etc` drop-in, not a visible `/sys` file). A probe change with no measured benefit is the wrong first step. | Verifier on 5.15, ring volume, the open flags of `echo > memory.max`. |
| `prlimit64` tracepoint | **Not made.** | It needs a new event or field, so a schema version, the next free one when it lands (the numbers move with every schema PR; main is at 62 and several open PRs have claimed the ones after it), so it would conflict with each until they merge. Without a tracepoint the only visible `prlimit` path is argv, which the run showed is empty for 3 of 3 execs. | Whether a tracepoint sees the target pid reliably. |
| Low alert for `prlimit --pid`, no tool named | **Kept.** | It costs nothing, it is Low, and the doc states how it is bypassed (whole-match `--as`, clustered short options, direct `setrlimit`, empty argv). Removing it would remove the only trace of the attempt. | Its false-positive rate on a real fleet. |
| Watching pid 1's write of `/etc/systemd/system.control/<unit>.d/*.conf` (seen in the run) | **Not built; recorded as the next step on #1138.** | It is a different detection shape (a write by the manager to a drop-in of a listed unit), and the run shows one file name pattern on one systemd version. It needs a second host (Rocky 9, systemd 252) before a rule keys on it. | Other systemd versions, `--runtime`, a unit with its own drop-in name. |
| Ancestor slice (`system.slice`) of a freeze or a limit | **Left silent, listed as a bypass** (review of #1145: SoFrexs offered to keep it or to treat the slice as the tool's cgroup). | Freezing or limiting `system.slice` acts on every service of the host, sshd included, and is far more often administration than an attack on one tool; alerting would make the Medium rule noisy. The tests pin it silent. | A fleet's rate of `systemctl freeze/set-property` on a slice. |
| Relative and `//` cgroup paths | **Read by the rule** (`cgroup_unit_and_file`). | They pass the probe filter today and reach the rule, unlike the canonical path. A relative path is read on `<unit>.service/<file>`, so a relative `auditd.service/memory.max` from an unrelated directory is a false positive for a listed tool's name only. | That these forms leave the probe on a VM; `openat` with a directory fd. |
| ADR number | **0046 kept**, renumber at merge. | 0044 is claimed by #1051 and 0045 by #1141; both are unmerged. | |
