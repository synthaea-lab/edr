# Security-tool stop (SECURITY-TOOL-STOP, #379)

One stateless rule over the exec stream: `check_security_tool_stop`
(`crates/rules/src/securitytool.rs`, run by `evaluate_exec`). It is the T1562.001 (Impair
Defenses: Disable or Modify Tools) line of the Defense Evasion pack (#379) that needs no new
telemetry, and it adds the one thing the neighbouring rules do not say: **which** service was
stopped.

## The shape

An exec that stops a service of a fixed list of security tooling, as the command line says it:
`systemctl stop|disable --now|mask --now|kill`, `service X stop`, `sc stop`, `net stop`,
`Stop-Service`, `launchctl bootout|unload|remove|stop`. The parser is the one of
SERVICE-STOP-BURST (`servicestop::services_stopped`): this rule asks which service, that one
counts how many. One alert per exec, T1562.001, **Medium**, naming the first listed service the
command stops.

| Platform | Services | Matched as |
| --- | --- | --- |
| Linux | `auditd`, `apparmor`, `falco` (and `-bpf`, `-modern-bpf`), `osqueryd`, `wazuh-agent`, `ossec`, `clamav-daemon`, `clamd`, `suricata`, `snort`, `sysmon`, `mdatp`, `falcon-sensor`, `sentinelone` | exact name, `.service` suffix ignored |
| Windows | `WinDefend`, `WdNisSvc`, `Sense`, `Sysmon64`, `SecurityHealthService`, `CSFalconService`, `SentinelAgent`, `CbDefense` | exact name, any case |
| macOS | launchd labels under `com.crowdstrike.`, `com.sentinelone.`, `com.microsoft.wdav`, `com.carbonblack.`, `com.apple.xprotect` | vendor prefix |

The product names are as the vendors' documentation gives them and were **not checked on a host**:
a wrong name costs a missed stop, never a false alert.

## What it does not duplicate

- **SERVICE-STOP-BURST** (T1489, #970) counts at least five distinct services from one lineage in a
  minute. A single `systemctl stop falco` is below it by design; a burst that includes a security
  tool raises both, which is the intent.
- **`audit_service_masked_now` and `audit_collection_disabled`** (Sigma, Linux) name `mask --now
  auditd` and `auditctl -e 0`. `auditd` is on this list as well, so `mask --now auditd` raises
  both findings, and `systemctl stop auditd` raises this one only.
- **T1562.002** (#800) owns the Windows `EventLog` service and the audit policy: `eventlog` is
  deliberately **not** on the list. The firewall services (T1562.004) are not either.
- **`check_security_process_signal`** (#362) is the kill half: the agent's own pid on every
  platform (the eBPF and Endpoint Security gates filter at the source), and on **Linux also the
  processes of a listed security unit** (#1103, [below](#signals-to-a-security-tool-linux-1103)).
  Its sender filter (#1103) reads the sender's pid only: pid 1 (the service manager, which
  delivers `systemctl stop`, a stop timeout's SIGKILL and an upgrade's restart) is Low and not
  dropped, since `systemctl kill` and a D-Bus stop arrive from pid 1 too. `systemctl kill` of a
  listed tool is read by the exec rule (below), which is the High-side record of who asked: before
  that verb was parsed, `systemctl kill -s KILL <tool>` left only this Low signal and no exec
  alert. A process signalling itself raises nothing. The event carries no sender unit or cgroup,
  so the watchdog or another process of the same unit is **not** told apart from an intruder.
- This agent's own service is **not** on the list: its package scripts stop it on every upgrade,
  and a stopped agent cannot alert on its own stop.

## Signals to a security tool (Linux, #1103)

A process that kills or stops a listed tool (`kill`, `pkill`, `tgkill`, `pidfd_send_signal`) is
seen by the `signal:signal_generate` tracepoint, which no command line shows and no journal job
record carries (a killed unit is `failed` with no stop job; `service auditd stop` writes none
either). The rule is `check_security_process_signal`; what it does with the signal depends on the
target:

| Signal to a listed tool | Severity | Why |
| --- | --- | --- |
| `SIGKILL`, `SIGSTOP` from a process other than pid 1 | High | cannot be handled: the tool is ended or frozen |
| `SIGTERM`, `SIGINT`, `SIGQUIT`, `SIGABRT` from a process other than pid 1 | Medium | an administrator's `kill <pid>`, or `service auditd stop` (its helper `auditctl` sends the `SIGTERM`, not pid 1), looks the same as an attacker's, like `systemctl stop` |
| any terminating signal from pid 1 | Low | `systemctl stop`, a stop timeout, an upgrade; the manager does not say who asked |
| A reload signal (`SIGHUP`, `SIGUSR1`, `SIGUSR2`, real-time) to a tool that **catches** it (`SigCgt` at scan time) | none | a reload (logrotate, `ExecReload=`, `systemctl reload`, Suricata's `SIGUSR2`); dropped **in the kernel**, so a storm of them cannot fill the ring ahead of a kill |
| the same signals to a tool with **no handler** | Medium | the default action ends it; reported like the other catchable signals (`SIGTERM`, `SIGINT`, `SIGQUIT`, `SIGABRT` are never treated as reloads: a handler for them is how a daemon shuts down) |
| `kill -0`, a tool signalling itself, a signal sent by the kernel (`SEND_SIG_PRIV`), `SIGCHLD` / `SIGCONT` / `SIGURG` / `SIGWINCH` | none | dropped in the kernel (`SEND_SIG_PRIV`, a signal outside the terminating set) or by the rule (self-signal). **No filter on `si_code`**: a null `siginfo` (`echo 1 > cgroup.kill`), a positive code (`fcntl` `F_SETSIG`) and a negative one are all reported, because a process picks its `si_code` with `rt_sigqueueinfo` / `pidfd_send_signal` (the kernel refuses only a non-negative one and `SI_TKILL` toward another process). For `SI_TIMER` / `SI_MESGQ` / `SI_ASYNCIO` the event is marked `sender_unreliable` and the alert says so |
| any other signal that ends a process by default (`SIGUSR1`, `SIGPIPE`, `SIGALRM`, real-time...) from a process other than pid 1 | Medium | reported as `signal N`; the tool dies of it unless it handles it, and which ones it handles is not known |

The agent's own pid keeps the older behaviour (`SIGHUP` included: the agent does not reload on it).

**How a target is recognised.** `SECURITY_SERVICES` are unit names, not process names, so the
sensor resolves each listed unit to its processes from the cgroup (`system.slice/<unit>.service`,
its sub-cgroups, and the hybrid cgroup v1 layout) and keeps the thread-group ids in a kernel hash
set, rescanned every 5 seconds. The probe is a **raw** tracepoint and compares the target task's
`tgid` (a BTF offset read at start), so a `tgkill` to any thread of a tool is the tool's, with no
thread list to keep fresh. The executable is read at scan time, because a `SIGKILL`ed target is
gone by the time its event is drained.

**Choices, and why:**
- *Tracepoint, not the `kill`/`tgkill` syscall probes.* Those compare the pid argument in the
  **sender's** pid namespace (a container's pid 400 matches a host tool's pid 400), cannot see
  `tkill` (a thread id) or `pidfd_send_signal` (a file descriptor), and never match `kill(-pgid)`.
  `signal_generate` has the target in the initial namespace, once per target.
- *Raw, not the formatted tracepoint.* The formatted record has the target's thread id only; the
  raw one hands over the task, whose `tgid` is exact. The cost is one BTF offset
  (`task_struct.tgid`), and the program is in `RAW_TRACEPOINTS`, so the agent's preflight loads it
  through the verifier with the others.
- *No `result` field, no wire change.* The delivery `result` was meant to tell a refused `kill`
  (`EPERM`) from a delivered one. Permission is checked **before** the tracepoint fires, so a
  refused signal never reaches it, and `result` only says "delivered, ignored or already
  pending". `WIRE_VERSION` stays 27; the unit is added in userspace (`target_unit`, schema 60).
- *Reload signals depend on the tool's handler.* `SIGHUP`, `SIGUSR1`, `SIGUSR2` and the real-time
  signals are what daemons catch to reload (logrotate, Suricata's `SIGUSR2`), but their default
  action ends a process, so hiding them for every tool was an evasion path (review of #1114).
  The scan reads each process's `SigCgt` (`/proc/<pid>/status`, at most 5 s old) into the value
  of its `SIGNAL_WATCH_TOOLS` entry, and the probe drops such a signal when the tool catches it:
  **in the kernel**, not in the drain, so a storm of them does not fill the ring ahead of a
  `SIGKILL`. A tool whose `SigCgt` could not be read counts as catching nothing: over-reporting
  is the safe error. Lab: `auditd` (catches `SIGHUP`, `SIGUSR1`, `SIGUSR2`) silent, a unit
  running `sleep` (no handler) Medium.
- *No filter on `si_code`; an unreliable sender is marked, not dropped.* The first cut dropped
  `SI_TIMER` / `SI_MESGQ` / `SI_ASYNCIO` as "from interrupt context". A process can choose those
  codes itself with `rt_sigqueueinfo` or `pidfd_send_signal`, so a `SIGKILL` sent with
  `si_code = -2` was invisible (review of #1114, reproduced in the lab: the event now alerts High).
  The probe sets a bit in the wire `signal` (`SIGNAL_SENDER_UNRELIABLE`, no layout or
  `WIRE_VERSION` change), userspace strips it and sets `SignalEvent::sender_unreliable` (inside
  schema 60, which this PR introduces: absent means false), and the alert adds that the sender is not
  reliable. For the three codes `current` really is a bystander when the kernel raised them.
- *Ignored and already-pending signals are dropped in the kernel.* The tracepoint also fires for a
  signal the target ignores or that is already queued; the probe reads its fifth argument
  (`result`, `enum sig_result`) and drops `TRACE_SIGNAL_IGNORED` (1) and
  `TRACE_SIGNAL_ALREADY_PENDING` (2). Review of #1114: `auditd` ignores `SIGPIPE`, and 20,000 of
  them ahead of a `kill -9` filled the ring and lost the kill. `SIGKILL` and `SIGSTOP` can be
  neither. A tool that blocks its reload signal for a `signalfd` (not in `SigCgt`) is covered too:
  the repeats are already pending. **Not verified**: the eBPF crate was not built here (no
  `bpf-linker`), only type-checked on the host, and the `SIGPIPE` storm re-run on a VM is for the
  reviewer.
- *Lost signals are an alert.* A full ring is counted per CPU (`SIGNAL_TOOL_DROPS`); when the
  count grows the sensor emits a `SignalEvent` with `signals_lost` set (no signal, no target:
  `signal` and `target_pid` are 0) and the rule `check_signal_events_lost` raises T1562.001
  **High**: what was lost may be the `SIGKILL`, and nothing after the fact says which signals they
  were (review of #1114: 20,000 ignored `SIGPIPE` ahead of a `kill -9` left only the loss report).
  The kernel drop of caught reloads and of ignored or already-pending signals removes the cheapest
  floods; a flood of lethal signals (`SIGTERM`) can still fill the ring, and is reported.
- *The loss has its own field, not a bit of `FileOpenEvent::flags`.* The first cut flagged a
  `FileOpenEvent` with `0x0040_0000`, which is `O_TMPFILE`'s bit: every `tmpfile()` open alerted
  (measured on Fedora 43, uid 1000 and root, `flags 0x490002`). `openat` ignores unknown flag bits
  and the probe reads the flags raw, so any bit of that field can be set by an unprivileged open:
  the loss moved to `SignalEvent::signals_lost` (inside schema 60), which only the sensor's report
  sets. Regression test: an `O_TMPFILE | O_RDWR` open gives no alert. **Not verified live**: the
  `O_TMPFILE` re-check on a VM is for the reviewer. `FLAG_UNIT_STOPPED` (`0x8000_0000`, #1085) has
  the same exposure to a raw `open` flag and is not changed here.
- *Medium for the catchable signals.* An administrator's stop and an attacker's are the same
  command; High is kept for what cannot be handled.

**Stated gaps.** A tool not run by a systemd unit, a template instance (`clamd@scan.service` is
not `clamd.service`), and a **restarted tool's new pid for up to 5 seconds** (the next scan) are
not watched. A sender in the tool's own unit (its watchdog) is not told apart from an intruder:
the event has no sender unit. The listed unit names were not checked on a host beyond `auditd`.

### Verification status

**Verified** (Fedora 43, kernel 7.2.9; Rocky 9.8, kernel 5.14, static musl build; observe-only;
captures under `lab/captures/test-1103-*` and `test-1114-20261103`):
- The verifier accepts `raw_signal_generate` on 5.14 and 7.2.9. Against `auditd`: `kill -0`
  nothing, `kill -9` High, `service auditd stop` (sender `auditctl`), `pkill`, `pidfd_send_signal`
  and a `tgkill` of a worker thread (reported under the process id) alerted with unit and exe,
  and a restarted tool was watched within the rescan.
- **cgroup v1 (hybrid) live** on Rocky 9.8: watch list of 2, `kill -9` of `auditd`, SIGTERM from
  pid 1 and `pkill` alerted.
- **A real vendor daemon**, Suricata 7.0.17 on Fedora, **before** the reload signals were dropped
  in the kernel (it then gave an event and no alert for SIGUSR2 and SIGHUP; the rule has since
  changed, see the next item for the current behaviour): `kill -9`, SIGTERM from pid 1, `pkill` and a `tgkill` of a worker thread
  alerted with unit `suricata`.
- **A signal storm** (about 240,000 SIGURG in 1 s) with a `kill` inside it lost nothing, on
  cgroup v2.
- **The review fixes of #1114** (Fedora 7.2.9, `auditd`): `echo 1 > cgroup.kill` High with the
  writing shell as sender; `fcntl` `F_SETSIG=SIGKILL` High with `python3` as sender; `SIGUSR1`
  Medium; `SIGWINCH`, `SIGCHLD` no event; a tool moved to another cgroup stayed watched and a
  later `SIGTERM` alerted; `SIGHUP` silent for `auditd`, Medium for a unit with no handler.
- **Third round of #1114** (same VM, `auditd`, captures `test-1114-20261103/run-r3`,
  `run-storm`): a **forged `si_code`** (`rt_sigqueueinfo`, python `ctypes` syscall 129,
  `SIGKILL` with `si_code = -2` from root) alerted High with "the sender is not reliable"; the
  same with `si_code = -6` (`SI_TKILL`) was refused by the kernel (`EPERM`, nothing killed).
  A **`SIGHUP` storm** to `auditd`, which catches it: 538,261 signals in 1.5 s with a `kill -9`
  at the end, and in a first run 20,252 signals with the kill after 50 ms: not one `SIGHUP`
  event reached userspace, the `SIGKILL` alerted High, and no loss was counted (`SIGNAL_TOOL_DROPS`
  stayed 0, no "signals lost" event). **Caught reloads on a synthetic unit** named `osqueryd`
  (not a real vendor tool): a python process with a `SIGUSR2` handler gave no event for
  `SIGUSR2`; `SIGUSR1` (no handler) Medium (`signal (10)`); a `sleep` unit hit by `SIGUSR2`
  Medium (`signal (12)`).
- **Real kernel-raised `SI_TIMER` and `SI_MESGQ`** (same VM and agent, synthetic unit `osqueryd`
  running a python process with no `SIGUSR1` handler, captures `run-timer`): a one-shot POSIX
  timer (`timer_create`, `SIGEV_SIGNAL`, `SIGUSR1`) armed by the process on itself ended it and
  was reported with `sender_unreliable: true`; the sender in `meta` was **pid 0, comm
  `swapper/5`**, the idle task of the CPU that took the timer interrupt: a bystander, neither the
  tool nor an attacker. The alert was Medium and said "the sender is not reliable". A real
  `SI_MESGQ` (`mq_notify` with `SIGEV_SIGNAL`, a forked child calling `mq_send`) was reported the
  same way, but the sender was the child (pid 1133, `python3`), the real sender, because the send
  runs in process context; it is flagged unreliable anyway.

**Not verified:** the storm on cgroup v1 (same probe and filter, only the rescan reads another
hierarchy: accepted by argument); a **full ring** (the storm of caught `SIGHUP` no longer reaches
it, and no run filled it with lethal signals, so the "signals lost" event is covered by unit tests
only); `SI_ASYNCIO` (an AIO completion with `SIGEV_SIGNAL`: only the forged code was run for it) and a timer signal the tool handles; Suricata
**after** the reload filter (the real daemon was not reinstalled: the synthetic unit stands in for
it, a python process with a `SIGUSR2` handler); a kernel older than 5.14 with the new probe;
`falco` and `osqueryd` as real tools. One VM per kernel, one week.

**Out of scope, by decision:** a tool in a container (ADR-0007 of the project vault).

### Known gaps

- **Containers.** The rule watches the processes of the listed **host systemd units**, resolved
  from the unit's cgroup. A tool in a container runs in a runtime scope that carries the
  container id, not the tool's name, so it is not watched. Its own follow-up issue.
- **A tool not run by a systemd unit**, a template instance (`clamd@scan.service` is not
  `clamd.service`), and a restarted tool's new pid for up to 5 s are not watched.
- **A sender in the tool's own unit** (its watchdog) is not told apart from an intruder: the
  event has no sender unit.
- **A stop through the service manager is Low** (sent by pid 1, which does not say who asked).
  It is not left alone: the exec rule `check_security_tool_stop` (Medium) reads `systemctl stop`
  and `systemctl kill`, and the journal source (#1085) reports a stop nobody explains.
- **Dependency on #1118.** That exec rule reads `argv`, which is empty for most short-lived
  commands (issue #1118, ADR-0045 in PR #1123): until it is fixed the manager-sent stop depends on
  a rule that often cannot see the command.
- **Signal attribution.** With `sender_unreliable` the `meta` of the event may be a bystander (`SI_TIMER`, `SI_MESGQ`, `SI_ASYNCIO`, or a forged code). Measured: for `SI_TIMER` the sender is a bystander (the idle task, `swapper/N`, or whatever ran when the interrupt fired); for `SI_MESGQ` it was the real sender in the run, so the marker is cautious there. `SI_ASYNCIO` was not run. A null `siginfo` (`SEND_SIG_NOINFO`) is attributed to the current task;
  other in-kernel callers that pass 0 to `send_sig` were not enumerated (a wrong sender is the
  safe error). `SigCgt` is as old as the last scan (at most 5 s): a process that drops its handler between two scans (a same-pid `exec`, for instance) has a lethal `SIGHUP`, `SIGUSR1`, `SIGUSR2` or real-time signal dropped in the kernel until the next scan. Not measured; read from the design (review of #1114).

## `systemctl kill`

`servicestop::services_stopped` reads `systemctl kill` as a stop when the signal ends or freezes
the unit: the default (SIGTERM), `KILL`, `INT`, `QUIT`, `ABRT`, `STOP`, by name (with or without
`SIG`) or number, in the forms `-s SIG`, `-sSIG`, `--signal=SIG` and `--signal SIG`. Not a stop:
`HUP` (the reload idiom), `USR1`/`USR2`, signal `0`, and `--kill-whom=control` (the stop script is
signalled, not the service). The option values are skipped, so the signal is never read as a unit.

Alerts: `check_security_tool_stop` (Medium, as for every stop verb) for a listed tool, and the
service-stop burst counts it. **Burst counts change:** a kill counts one distinct service per
unit named, like a stop, so `systemctl kill -s KILL a b c d e` is a burst and a mix of stops and
kills adds up; reloads add nothing. Counted on purpose: SIGKILL of a unit takes it down as a stop
does, an intruder uses it to skip the stop job's timeout, and five distinct units killed in a
minute is not maintenance.

## Provisional and stated gaps

- It reads the **command**, not the outcome: a stop that is refused (`sc stop WinDefend` is denied on
  a current Windows), or any stop that does not go through these commands (`kill`, `pkill`,
  `taskkill`, D-Bus, an API call, `setenforce 0`, `aa-teardown`), is not seen. The journal
  sensor now reports the **stop of a listed unit** (`FileOpenEvent` with `FLAG_UNIT_STOPPED`, #1085,
  filtered at the sensor, system manager only, the record's writer checked as PID 1) but names no
  actor, and no rule consumes it yet (stacked work); and the macOS unified-log tail emits TCC, `sudo` and Gatekeeper records.
- A service-name list is a list: a tool not on it is not covered. Windows display names (`net stop
  "Windows Defender Antivirus Service"`) are not matched, only service names.
- **Expected false positives, hence Medium**: an administrator stopping `auditd` or `clamav-daemon`
  to debug or upgrade, a package script, configuration management, an uninstall of an agent.
  Nothing is excluded by process name.

**Review fixes of PR #1114.** The kernel filter keeps only the terminating signals (`TOOL_SIGNALS`
in `raw.rs`), so a sender cannot fill the shared ring with `SIGCONT` or `SIGWINCH`
ahead of a `SIGKILL`; a full ring is counted per CPU (`SIGNAL_TOOL_DROPS`) and reported by the
rescan. A watched tool that leaves its unit's cgroup stays watched until it exits. A drained event
whose target left the scan is named from the previous scan too, and one that matches nothing gets
no image and no unit (never the agent's). `SIGNAL_WATCH_TOOLS` holds `SIGNAL_WATCH_TOOLS_ENTRIES` (8192) entries, checked at compile time
against `SECURITY_SERVICES.len()` (24) times `MAX_PROCS_PER_UNIT` (6144, plus headroom for moved
tools and failed removals); a unit past the process cap, or with more cgroups than
`MAX_CGROUPS_PER_UNIT`, is logged (the second only when a directory was left unread).

A tool that left its unit's cgroup stays watched while it is the same process (same pid and start
time, `/proc/<pid>/stat` field 22); without a start time recorded at scan it is dropped. A failed
removal from the kernel set is retried at the next scan and the pid stays named until it succeeds.
