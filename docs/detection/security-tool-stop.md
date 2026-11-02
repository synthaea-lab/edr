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
  `taskkill`, D-Bus, an API call, `setenforce 0`, `aa-teardown`), is not seen by this rule. On
  Linux, the journal sensor reports the **stop of a listed unit** (`FileOpenEvent` with
  `FLAG_UNIT_STOPPED`, #1085, filtered at the sensor, system manager only, the record's writer
  checked as PID 1) but names no actor; UNEXPLAINED-UNIT-STOP covers it, below. The macOS
  unified-log tail emits TCC, `sudo` and Gatekeeper records, no unit lifecycle.
- A service-name list is a list: a tool not on it is not covered. Windows display names (`net stop
  "Windows Defender Antivirus Service"`) are not matched, only service names.
- **Expected false positives, hence Medium**: an administrator stopping `auditd` or `clamav-daemon`
  to debug or upgrade, a package script, configuration management, an uninstall of an agent.
  Nothing is excluded by process name.

## UNEXPLAINED-UNIT-STOP (T1562.001, #1085, Linux)

`crates/rules/src/unitstop.rs`. The journal sensor reports a stop of a unit of
`schema::SECURITY_SERVICES` as a `FileOpenEvent` with `FLAG_UNIT_STOPPED`; the journal names no
actor. The rule queues each stop and judges it once the stream clock is 120 s past it, so that a
start that follows can be seen. It alerts, Medium, unless the stop is explained:

| Explained by | Window | Read from |
| --- | --- | --- |
| an exec that stopped the same unit (the exec rule above already alerted: no second alert) | up to 120 s before the record (a stop job can last `DefaultTimeoutStopSec`, 90 s), 5 s after for clock skew | `systemctl stop`, `disable --now`, `mask --now`, `service X stop`, `/etc/init.d/X stop` |
| a restart or a start of the same unit | a restart exec like the one above; a start up to 120 s after the stop (a package upgrade stops in its pre-remove script and starts in post-install) | `systemctl restart|try-restart|start|reload-or-restart|enable --now`, `service`, `invoke-rc.d`, `deb-systemd-invoke` |
| the host shutting down | up to 300 s after the exec | an **immediate** `shutdown` (`now`, `+0`; not `-k`, not a `+N`/`HH:MM` schedule), `reboot`, `poweroff`, `halt` (but not with `-w`/`--wtmp-only`, which writes the wtmp record and leaves the host running), `systemctl reboot|poweroff|halt|kexec`, `init`/`telinit 0|6` |

The windows are choices, not measurements (no fleet data), and are named constants in the module.

A shutdown or a start is read from the **name** of the program, and each one silences an alert, so
it counts only when the image path is a system path or unknown (`policy::name_exclusion_applies`),
and an init script only from `/etc/init.d/`: a copy of `true` named `/tmp/reboot` or
`/tmp/systemctl` explains nothing. A `systemctl` (or `deb-systemd-invoke`) call with `--user`,
`--host`/`-H` or `--machine`/`-M` acts on a user manager, another host or a container, so it
neither starts a local unit nor opens the shutdown window. A start is a **claim** the rule does not
see succeed: a `systemctl start` that fails (a masked unit, a unit that does not exist) still
explains the stop.

Stated gaps: **no shutdown signal exists in the stream** (the journal sensor reports unit stops of
the listed services only, and SERVICE-STOP-BURST counts execs), so a shutdown is read from the
exec that asks for it; one asked another way (power button, logind from a desktop session, an ACPI
request) has its stops alert.
A **scheduled** shutdown (`shutdown +60`, `shutdown 23:00`, a bare `shutdown` which is `+1`, `systemctl reboot --when=…`) stops nothing yet and does not open the window, so it cannot cloak a stop; `shutdown -c`/`--cancel` (and `--when=cancel`) closes a window already open. The cloak `shutdown +99`, stop the tool, `shutdown -c` is therefore handled, and a scheduled shutdown that does fire has the stops of its own run alert (the cost of not trusting a command that only promises one). The same cloak without a schedule to cancel — `reboot -w`, which only writes the wtmp record — is handled the same way, by reading the flag. A start that no exec
shows (systemd's own `Restart=` after a crash, a socket activation) is not seen as one, so the
stop that preceded it alerts. A judged stop waits for a later exec or file-open event to move the
clock, so on a host with none the alert is late. A stop over D-Bus by an administrator is
indistinguishable from an intruder's, hence Medium. `systemctl stop` run by pid 1 on behalf of
another process is likewise a record with no actor.
