# ADR-0026: Sysmon on Windows: a supplementary, opt-in source for what we cannot yet collect natively

- **Status**: proposed
- **Date**: 2026-10-06

## Context

#286 asks whether the Windows sensor should subscribe to the
`Microsoft-Windows-Sysmon/Operational` channel when Sysmon is installed, and consume its
event ids (1, 3, 7, 11, 13, 22, ...) as normalized events. Technically it is a small
change: the poll targets added for AppLocker, WDAC and Defender (#283, ADR-0006) extend to
one more channel. The issue keeps it an architecture question because of duplication with
native ETW, Sysmon version churn, and a vision question (EDR or Sysmon aggregator). It
lists five questions; this ADR answers them.

Three facts changed or sharpened the picture since #286 was written.

**1. Sysmon is becoming part of Windows, not fading.** The issue says Microsoft has been
deprioritizing Sysmon. In November 2025 Microsoft announced Sysmon as a native Windows 11
and Windows Server 2025 feature, and it reached Insider builds in early 2026: off by
default, enabled from Settings or with PowerShell/DISM, and writing to the Windows Event
Log ([BleepingComputer][bleeping], [Petri][petri], [Techzine][techzine]). Hosts that can
produce Sysmon events will therefore grow without anyone deploying the Sysinternals
package. *Not verified here:* the channel name and event schema of the native build; they
must be captured from a real host before any parser is written (the rule this repository
follows for every channel: #283 found that the real data differs from the documentation).

**2. The Sigma catalogue gap is not a Sysmon gap.** The argument for Sysmon is that most
public Sigma rules are written against Sysmon. They are written against a *logsource
category* (`process_creation`, `network_connection`, `image_load`, `dns_query`,
`registry_set`, ...) and Sysmon-style field names (`Image`, `CommandLine`, `ParentImage`,
`DestinationIp`, ...). Sysmon is one backend for those categories; ours can be another.
Today `crates/sigma` supports only `Image`, `CommandLine` and `ParentImage` on
`ExecEvent` and does not read `logsource` at all (`crates/sigma/src/lib.rs`). Most of the
catalogue cannot run on this agent because of that mapping, whether or not Sysmon is
present. Ingesting Sysmon would not fix it: the rules would still need a field mapping
onto whatever event carries the data.

**3. Most Sysmon events duplicate what we already collect.**

| Sysmon EID | Meaning | Native today |
|---|---|---|
| 1 | Process create | `Exec` (ETW Kernel-Process) |
| 3 | Network connect | `Connect` (ETW Kernel-Network) |
| 7 | Image load | `ImageLoad` |
| 11 | File create | `FileOpen` (ETW) |
| 12, 13, 14 | Registry | `RegistrySet` (ETW Kernel-Registry) |
| 19, 20, 21 | WMI filter, consumer, binding | `WmiActivity` (ETW WMI-Activity) |
| 22 | DNS query | `DnsQuery` |
| 2, 9, 15, 23, 26 | Timestomp, raw read, ADS, file delete | planned: minifilter (#136) |
| 8, 10 | Remote thread, process access (LSASS) | planned: `ObRegisterCallbacks` / TI-ETW (#137) |
| 16 | Sysmon configuration changed | none |
| 17, 18 | Named pipe created, connected | none |
| 25 | Process tampering (hollowing, herpaderping) | none |

## Decision

Consume Sysmon, **as a gap filler and never as an aggregator**.

1. **Do we consume it at all?** Yes, but only the events we cannot collect natively.
   Sysmon is not a prerequisite of any shipped detection and never replaces a native
   source. If the native collectors ship (#136, #137), the Sysmon events they replace are
   dropped from the allowlist in the same release.
2. **Opt-in or auto-detected?** Opt-in, off by default, in `agent.toml`
   (`[windows] sysmon = "off" | "auto"`). `auto` subscribes when the channel exists and
   is enabled, and does nothing otherwise. The agent never installs, enables, updates or
   configures Sysmon, and never writes its configuration: that is the operator's, and a
   security agent that rewrites another security tool's filters is a liability.
3. **Duplication with native ETW?** Avoided by construction rather than deduplicated: the
   subscription query names only the allowlisted event ids, which have no native
   equivalent at the time of the release. The first allowlist is 8, 10, 15, 16, 17, 18
   and 25, plus 2, 9, 23 and 26 while #136 has not shipped. No correlator dedup logic is
   written, because no event arrives twice. Events keep their own schema variants with
   `source` carried by the variant, not a flag on a shared one.
4. **Which versions?** A tolerant parser keyed by numeric event id and field *name* (the
   approach #283 took for the localized Defender channel), ignoring unknown fields.
   Golden fixtures are captured from the current Sysinternals release and from the
   Windows-native build, on a real host. Older releases are best effort and untested; the
   supported set is stated in the docs and moves with the fixtures.
5. **An operator configuration that filters out what we expect?** We cannot see a filter,
   so we make silence visible instead of assuming. The channel gets a liveness heartbeat
   and a per-event-id last-seen counter like the other eventlog targets, and the health
   output reports "Sysmon enabled, no event 10 seen in N hours". A rule that needs Sysmon
   data declares it, and a missing source is reported as a degraded detection, not as
   "no findings". A Sysmon service stop, driver unload or configuration change (EID 16)
   is itself a finding (T1562.001): it is the one Sysmon signal worth having even for
   an operator who relies on native collection alone.

Separately, and not part of this decision: widening `crates/sigma` so `logsource`
categories map onto native events and the usual field names resolve. That, not Sysmon, is
what opens the public rule catalogue. It gets its own issue and, if it needs one, its own
ADR.

## Consequences

- The Windows sensor gains one opt-in channel with a short, explained allowlist, instead of
  an open-ended second event pipeline. The work is small and bounded.
- Hosts with Sysmon get process access, remote thread and named-pipe visibility *before*
  our own driver work (#136, #137) lands, and lose nothing when it does.
- A deployment that never enables Sysmon is unaffected: same events, same volume.
- We take on a parser per Sysmon event id and a fixture set per supported release, and the
  native-Sysmon schema is unknown until captured. The first implementation step is a lab
  capture, not code.
- The "EDR or Sysmon aggregator" question is settled in favour of the EDR: native
  collection stays the product, Sysmon fills named gaps and is retired from each as the
  native source replaces it.
- The allowlist and its shrinking are a maintenance commitment each time #136 or #137
  ships.

## Alternatives considered

- **Reject: do not consume Sysmon.** Simplest, and consistent with the native-first vision.
  Gives up process access, remote thread and pipe events on every Sysmon host until our
  driver ships, and gives up Sysmon tamper detection. Reasonable if the team prefers to
  keep the sensor surface minimal; the cost is a visibility gap we already know about.
- **Aggregate: consume every Sysmon event as a first-class source.** Adds the duplication
  problem the issue describes (each process and connection twice) for no visibility we do
  not already have, and makes correlation depend on an optional tool. Rejected.
- **Auto-enable when Sysmon is detected.** Turns on a second pipeline on hosts whose
  operator did not ask for it, and changes event volume after a Sysmon install. Rejected
  for opt-in.

## Follow-up issues (to open if this is accepted)

1. Lab capture of the Sysmon channel on a Sysinternals install and on a Windows-native
   build: channel name, event schema, volumes, the event ids of the allowlist.
2. `sysmon` configuration switch, poll target, heartbeat and per-id counters.
3. Schema variants and parsers for the allowlisted event ids, with golden fixtures.
4. Sysmon tamper rule (service stop, driver unload, EID 16), T1562.001.
5. `crates/sigma`: `logsource` category mapping and field mapping onto native events.

[bleeping]: https://bleepingcomputer.com/news/microsoft/microsoft-rolls-out-native-windows-11-sysmon-security-monitoring
[petri]: https://petri.com/microsoft-native-sysmon-windows-11/
[techzine]: https://techzine.eu/news/security/138521/windows-11-gets-built-in-sysmon-for-security-detection
