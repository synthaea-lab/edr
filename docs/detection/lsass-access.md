# LSASS access (LSASS-ACCESS, LSASS-REMOTE-THREAD, #960)

Two Windows rules over the driver-free telemetry of #720 (`docs/sensors/windows.md`, "LSASS
access" and "Remote threads"): `RuleState::on_process_access` (`crates/rules/src/state.rs`) and
`rules::evaluate_remote_thread`, with the decisions in `crates/rules/src/lsass.rs`. They are the
T1003.001 flagship the Credential Access pack (#377) left open until there was telemetry to
read. Neither is approximated from process creation or file events (#960).

| Rule | Event | Technique | Severity |
| --- | --- | --- | --- |
| LSASS-ACCESS | `ProcessAccessEvent`: an open of the system LSASS asking for a right that reads its memory | T1003.001 | High when granted, Medium when denied |
| LSASS-REMOTE-THREAD | `RemoteThreadEvent` whose owner is the system LSASS | T1055 | High |

LSASS is `lsass.exe` directly in a `System32` directory at a trusted system path; an `lsass.exe`
anywhere else is neither the target of an access alert nor of a thread alert. The sensor applies
the stricter check (the path under `%SystemRoot%`) before it builds the access event.

## Grading

The outcome grades LSASS-ACCESS, not the access mask. A granted open has read access to the
credentials in LSASS memory. A denied open is an attempt that a protected LSASS (`RunAsPPL`)
refused, and alerts Medium with its `NTSTATUS`. The mask does not rank intent: Mimikatz's
`sekurlsa` asks for the smallest mask that reads memory (`0x1010`), the same shape as a process
viewer, while `MiniDumpWriteDump` callers ask for more. The alert names the memory-read rights
in the mask so an analyst sees which one it was.

One alert per (caller pid, outcome) per five minutes, from a sliding counter in a bounded map.
The sensor already folds an identical open (caller, mask, status) into one event per minute, so
a dumper trying several masks is one finding, and a denied attempt followed by a granted one is
two.

## Expected readers

Excluded, each only with evidence (`lsass::is_known_reader`):

- `wininit.exe`, which starts and supervises LSASS;
- `csrss.exe`, the Win32 subsystem server, which holds a handle to every Win32 process;
- `MsMpEng.exe` (Defender's engine) and `MsSense.exe` (Defender for Endpoint), which scan
  process memory.

When the rule engine saw the caller's exec, the exec-time image decides: its name must be one
of these and it must sit at a trusted system path (`policy::name_exclusion_applies`) or, for
Defender, under `%ProgramData%\Microsoft\Windows Defender\Platform\`, which only `SYSTEM` and
`TrustedInstaller` write. An `MsMpEng.exe` run from `C:\Users\Public` alerts, and so does a
`rundll32.exe` whose sensor-side name is `csrss.exe`. When no exec was seen, which is the usual
case for these long-lived processes started before the agent, the process name the sensor
reports is the only evidence and the exclusion applies on it, as everywhere else.

Never excluded, each being a documented way to dump LSASS: `WerFault.exe` (the silent-process-
exit dump), `Taskmgr.exe` ("Create dump file"), `rundll32.exe` (`comsvcs.dll,MiniDump`), and the
generic hosts `svchost.exe` and `wmiprvse.exe`, whose names would exempt any DLL loaded into
them. The agent does not open LSASS for reading: it reads a process's command line with
`PROCESS_VM_READ` only when that process starts, and LSASS starts before the agent.

LSASS-REMOTE-THREAD has no expected creator. The kernel's threads, LSASS's own and the initial
thread of a new process never reach the event.

## Gaps

- **Not calibrated.** #715 measured how many opens and thread starts a host produces, not who
  opens LSASS. The reader list is the documented one; the first fleet or lab capture of the
  callers is where it grows, and an operator who runs a third-party antivirus or backup agent
  that reads LSASS sees it alert until then.
- **Unknown caller image.** For a process that predates the agent the exclusion rests on the
  sensor's process name. The sensor's pid store knows that process's image (it is seeded at
  start), so carrying the caller's image in `ProcessAccessEvent` would close this; it is a
  schema change left to a follow-up.
- **Not live-verified.** The telemetry of #720 has not run through the agent's real-time
  consumer on an elevated host yet, so neither rule has seen a real `procdump`, `comsvcs`
  `MiniDump` or `CreateRemoteThread` into LSASS. The unit tests pin the decisions above.
- **Out of reach of this telemetry:** a duplicated LSASS handle, injection without a new thread
  (APC, hijacked context), anything from the kernel (#137), and a dump of LSASS taken offline
  (a hibernation file, a VM snapshot).
