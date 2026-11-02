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
| `SIGHUP` | none | a daemon reads it as "reload your configuration" (logrotate, `ExecReload=`, `systemctl reload`) |
| `kill -0`, a tool signalling itself, a signal sent by the kernel | none | dropped in the kernel (code `<= 0`, a null or special `siginfo`) or by the rule |

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
- *`SIGHUP` is not an alert for a tool.* It is the commonest benign signal a daemon gets and the
  issue asks for a benign test on it. The price is stated: a tool with no `SIGHUP` handler is
  ended by it, and that is not seen here.
- *Medium for the catchable signals.* An administrator's stop and an attacker's are the same
  command; High is kept for what cannot be handled.

**Stated gaps.** A tool not run by a systemd unit, a template instance (`clamd@scan.service` is
not `clamd.service`), and a **restarted tool's new pid for up to 5 seconds** (the next scan) are
not watched. A sender in the tool's own unit (its watchdog) is not told apart from an intruder:
the event has no sender unit. The listed unit names were not checked on a host beyond `auditd`.

**Verified** on the Fedora 43 lab VM (kernel 7.2.9, the agent built from this branch, observe-only)
**and on the Rocky 9.8 VM (kernel 5.14, the static musl build, `auditd` 3.1.5)**, with the same
scenario (`lab/captures/test-1103-20261102/run-1103.sh`, `run-1103-rocky.sh`): the verifier accepts
`raw_signal_generate` on both kernels; against `auditd`, `kill -0` raised nothing, `kill -HUP`
produced an event and no alert, `kill -9` alerted High (and escalated), and `service auditd stop`
(sender `auditctl`), `pkill -x auditd` and a `pidfd_send_signal` (sender `python3`) each alerted
once with the unit and the exe in the event; a `tgkill` of a **worker thread** was reported under
the process id; and a restarted `auditd` (new pid) was watched within the rescan, twice per
kernel. **Not verified:** a real vendor tool other than `auditd` (none is installed in the lab),
a tool in a container, the cgroup v1 layout on a live host, the volume of `signal_generate` on a
busy host (the probe exits after one hash lookup for any other target), and a kernel older than
5.14. One VM per kernel, one day.

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
