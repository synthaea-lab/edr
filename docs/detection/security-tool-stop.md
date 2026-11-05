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
- **`check_security_process_signal`** (#362) is the kill half, and only for the agent's own pid:
  the eBPF and Endpoint Security gates filter at the source. Another vendor's tool killed with
  `kill` is not seen by it. Its sender filter (#1103) reads the sender's pid only: pid 1 (the
  service manager, which delivers `systemctl stop`, a stop timeout's SIGKILL and an upgrade's
  restart) is Low and not dropped, since `systemctl kill` and a D-Bus stop arrive from pid 1 too.
  `systemctl kill` of a listed tool is read by the exec rule (below), which is the High-side
  record of who asked: before that verb was parsed, `systemctl kill -s KILL <tool>` left only this
  Low signal and no exec alert. A process
  signalling itself raises nothing; any other sender is High. The event carries no sender unit or
  cgroup, so the watchdog or another process of the same unit is **not** told apart from an
  intruder and stays High.
- This agent's own service is **not** on the list: its package scripts stop it on every upgrade,
  and a stopped agent cannot alert on its own stop.

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

## Kernel-mediated stops (#1138)

A process can make the kernel end or freeze a tool with no signal the `signal_generate` probe
reports (`SEND_SIG_PRIV` signals are dropped, `cgroup.freeze` sends none). Traced in the kernel
source (v6.12) and **measured once on a Fedora 43 VM (2026-11-05)**, see the list after the table.
What is covered, and what is not (ADR-0046):

| Path | Coverage | Where |
| --- | --- | --- |
| `systemctl freeze <tool>`, `systemctl set-property <tool> MemoryMax=\|MemoryHigh=\|TasksMax=` | Medium, T1562.001, by command (`check_security_tool_throttle`) | exec stream |
| `prlimit --pid N --cpu=...` / `--as=...` | Low, T1562.001, **target not resolved to a tool** | exec stream |
| write to `memory.max`, `memory.high`, `cgroup.freeze`, `pids.max` (and v1 `memory.limit_in_bytes`, `memory.soft_limit_in_bytes`, `freezer.state`) of a listed unit's cgroup | rule written (`check_security_tool_cgroup_write`, Medium, pid 1 skipped), **no event reaches it yet** | `FileOpenEvent` |
| `prlimit64` syscall on a watched tgid | not built | needs a probe |

The cgroup-file rule is the contract of a probe change that needs a VM: `is_filtered_path` drops
`/sys/` unconditionally, so the open never leaves the kernel. Same limits as the exec rules above:
argv-based, hence bypassable (`echo` through a shell redirection has no argv at all, which is why
the file rule exists) and blind when `argv` is empty (#1118). `systemctl freeze` and
`set-property` reach the cgroup through pid 1, so the file rule skips pid 1 and the exec rule is
the only one that sees them.

Measured on the VM (agent build without these rules, observe-only, synthetic `osqueryd.service`):

- No `file_open` reaches the agent for any `/sys/fs/cgroup/` path, for sh, python or pid 1: the file
  rule has no producer until the probe change. A `file_write` event exists (fd and byte count, no
  path), which does not identify the file. A write elsewhere (`/tmp`) did produce `file_open`.
- `systemctl set-property` is written by pid 1, as an open of
  `/etc/systemd/system.control/<unit>.d/50-<Property>.conf`, not a `/sys/` open.
- argv was empty for 5 of 8 `systemctl` execs (`freeze`, `thaw`) and 3 of 3 `prlimit` execs, so the
  exec rules are blind on this build for most short-lived calls (#1118).
- No `signal` or `unit_stop` event for freeze, set-property, direct writes, `prlimit` or an OOM kill
  (only a plain `systemctl stop` gives `unit_stop`).

Not measured: the new rules on a VM, a real OOM or CPU-limit kill of a tool's main process,
`--runtime`, cgroup v1, the probe change, the `prlimit64` tracepoint.
