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
  sensor now reports the **stop of a listed unit** (`schema::UnitStopEvent`, #1085,
  filtered at the sensor, system manager only, the record's writer checked as PID 1; an event of its
  own, not a flag on a `FileOpenEvent`, because a raw `openat` flag can carry any bit and an
  unprivileged open could have raised the finding, as `O_TMPFILE` did for the signal-loss bit, ADR-0008) but names no
  actor; UNEXPLAINED-UNIT-STOP consumes it, below. The macOS unified-log tail emits TCC, `sudo` and Gatekeeper records.
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

## UNEXPLAINED-UNIT-STOP (T1562.001, #1085, Linux)

`crates/rules/src/unitstop.rs`. The journal sensor reports a stop of a unit of
`schema::SECURITY_SERVICES` as an `Event::UnitStop` (#1127: an event of its own that only the journal sensor builds, from a record written by the system manager, so an `openat` flag cannot forge it; a `FileOpenEvent` naming a listed unit is not a stop, and a test pins that). The journal names no
actor. The rule queues each stop and judges it once the stream clock is 120 s past it, so that a
start that follows can be seen. It alerts, Medium, unless the stop is explained:

| Explained by | Window | Read from |
| --- | --- | --- |
| an exec that stopped the same unit (the exec rule above already alerted: no second alert) | up to 120 s before the record (a stop job can last `DefaultTimeoutStopSec`, 90 s), 5 s after for clock skew | `systemctl stop`, `disable --now`, `mask --now`, `service X stop`, `/etc/init.d/X stop` |
| a restart or a start of the same unit | a restart exec like the one above; a start up to 120 s after the stop (a package upgrade stops in its pre-remove script and starts in post-install) | `systemctl restart|try-restart|start|reload-or-restart|enable --now`, `service`, `invoke-rc.d`, `deb-systemd-invoke` |
| the host shutting down | up to 300 s after the exec | an **immediate** `shutdown` (`now`, `+0`; not `-k`, not a `+N`/`HH:MM` schedule), `reboot`, `poweroff`, `halt` (only with argv captured and every option one of `-f -d -n -p`, `--force --no-wtmp --no-sync --no-wall --poweroff --reboot --halt`; `-w`, `--help`, a bad option or no argv gives no window), `systemctl reboot|poweroff|halt|kexec`, `init`/`telinit 0|6` |

The windows are choices, not measurements (no fleet data), and are named constants in the module.

A shutdown or a start is read from the **name** of the program, and each one silences an alert, so
it counts only when the image path is a system path or unknown (`policy::name_exclusion_applies`),
and an init script only from `/etc/init.d/`: a copy of `true` named `/tmp/reboot` or
`/tmp/systemctl` explains nothing. A `systemctl` (or `deb-systemd-invoke`) call with `--help`, `--version` or `--dry-run` only prints, so it neither starts a unit nor opens the window. A `systemctl` (or `deb-systemd-invoke`) call with `--user`,
`--host`/`-H` or `--machine`/`-M` acts on a user manager, another host or a container, so it
neither starts a local unit nor opens the shutdown window. A start is a **claim** the rule does not
see succeed: a `systemctl start` that fails (a masked unit, a unit that does not exist) still
explains the stop, and so does one run with an option `systemctl` refuses (`--bogus`,
`--dry-run=yes`); a `systemctl --bogus reboot` opens the shutdown window the same way. The
rule does not parse the option set of `systemctl`; the `reboot`, `poweroff` and `halt` options are
the only ones it checks against an allowlist.

Stated gaps: **no shutdown signal exists in the stream** (the journal sensor reports unit stops of
the listed services only, and SERVICE-STOP-BURST counts execs), so a shutdown is read from the
exec that asks for it; one asked another way (power button, logind from a desktop session, an ACPI
request) has its stops alert.
A `reboot`, `poweroff` or `halt` whose argv was not captured (the usual case, #1118) opens no window: its options are unknown and `reboot -w` cannot be told from a real reboot, so a real reboot whose argv was missed has its stops alert, the same cost as a scheduled shutdown, until the pid-1 target record below replaces this parsing.
A **scheduled** shutdown (`shutdown +60`, `shutdown 23:00`, a bare `shutdown` which is `+1`, `systemctl reboot --when=…`) stops nothing yet and does not open the window, so it cannot cloak a stop; `shutdown -c`/`--cancel` (and `--when=cancel`) closes a window already open. The cloak `shutdown +99`, stop the tool, `shutdown -c` is therefore handled, and a scheduled shutdown that does fire has the stops of its own run alert (the cost of not trusting a command that only promises one). A start that no exec
shows (systemd's own `Restart=` after a crash, a socket activation) is not seen as one, so the
stop that preceded it alerts. A judged stop waits for a later exec, file-open or unit-stop event to move the
clock, so on a host with none the alert is late. A stop over D-Bus by an administrator is
indistinguishable from an intruder's, hence Medium. `systemctl stop` run by pid 1 on behalf of
another process is likewise a record with no actor.

### Known limits

**The explanations that read an exec depend on its `argv`, which is empty for most short-lived
commands (#1118).** The Linux sensor reads `argv` from `/proc/<pid>/cmdline` when the exec event is
drained, and a process that has already exited has no entry. This affects condition 1 ("an exec
stopped the same unit just before") and the shutdown and start joins in the table above, because they
all match on the command line. Measured on Fedora 43 (kernel 7.2.9) and Rocky 9.8 (kernel 5.14), with
the agent of `main` at `81cc6c52` for the empty-`argv` rate: `systemctl` has an empty `argv` in
97 to 100 % of its execs, idle or loaded, and `sudo` in 86 to 98 %. A `/usr/bin/true` or a
`sleep 0.3` is read fine when idle and mostly missed with one `yes` per vCPU running. With the PR
#1102 agent, 12 `systemctl stop` of synthetic units named like listed tools (two rounds of six) gave
the same result on both systems: 11 of the 12 reached UNEXPLAINED-UNIT-STOP, and 1 was explained by
the exec (the one whose `argv` was captured). **Each stop still alerted exactly once, but 11 times
with a reason that is wrong**: the message says no `systemctl stop` of the unit was seen, although
one ran. The rule does not miss the stop; its explanations rarely hold. Not measured: a process that
exits more slowly than a few ms under a load other than `yes` (one per vCPU), and the effect of #1116
(which bounds `argv` at capture) on this rate. Captures: `lab/captures/test-1118-20261103/` and
`lab/captures/test-1085b-20261103/`; notes in `issues/issue-1085.md` and `issues/issue-1118.md`.

**Decision of the owner (delegated, 2026-11-03): the long-term source for "the host is shutting
down" is the manager's own journal record, not the exec.** That record is a pid-1 entry
(`_PID=1`, `JOB_TYPE=start`, `JOB_RESULT=done`) for `reboot.target`, `poweroff.target`,
`halt.target`, `kexec.target` or `shutdown.target`. Measured on Fedora 43 (systemd 258,
`lab/captures/test-1109-20261103/`): a real `systemctl reboot` writes such records (`reboot.target`,
`systemd-reboot.service`, `shutdown.target`, `final.target`) and a hypervisor power-off writes
`poweroff.target` the same way, while `reboot -w`, `halt -w`, `shutdown +99` then `shutdown -c`,
`systemctl reboot --dry-run` and `reboot --help` write none. Reading the shutdown from the exec's
command line is therefore a **stopgap**: it has an open-ended list of tool spellings (systemd,
sysvinit, busybox) and, per #1118, an empty `argv` for most of these commands anyway. The reasoning
and the other options are in `issues/decisions-delegated-2026-11-03b.md`. Not built: the journal
sensor change for the target records. Not measured: whether the target record comes after the listed
unit's own stop in a real shutdown, and whether a shutdown on a loaded host is slow enough for the
agent to judge the queued stops.
