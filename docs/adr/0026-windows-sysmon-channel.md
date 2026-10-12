# ADR-0026: Sysmon on Windows: a supplementary, opt-in source for what we cannot yet collect natively

- **Status**: accepted
- **Date**: 2026-10-07

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
deprioritizing Sysmon. In November 2025 Mark Russinovich announced Sysmon functionality as
a native Windows 11 and Windows Server 2025 feature on the Windows IT Pro blog
([Microsoft][ms]). Press coverage of the Insider builds that followed reports it off by
default, enabled from Settings or with PowerShell/DISM, and writing to the Windows Event
Log ([Petri][petri], [Techzine][techzine]). Hosts that can produce Sysmon events will
therefore grow without anyone deploying the Sysinternals package. *Not verified here:* the
channel name and event schema of the native build; they must be captured from a real host
before any parser is written (the rule this repository follows for every channel: #283
found that the real data differs from the documentation).

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

**3. Most Sysmon events duplicate what we already collect, and two of the gaps may close
without a driver.**

| Sysmon EID | Meaning | Native today |
|---|---|---|
| 1 | Process create | `Exec` (ETW Kernel-Process) |
| 3 | Network connect | `Connect` (ETW Kernel-Network) |
| 7 | Image load | `ImageLoad` |
| 11 | File create | approximately `FileOpen` (ETW): an open, of which a creation is one kind |
| 12, 13, 14 | Registry | `RegistrySet` (ETW Kernel-Registry) |
| 19, 20, 21 | WMI filter, consumer, binding | `WmiActivity` (ETW WMI-Activity) |
| 22 | DNS query | `DnsQuery` |
| 15 | Alternate data stream created | `Zone.Identifier` streams: `FileQuarantine` (#365), their removal `FileDelete` (#442); other streams planned: minifilter (#136) |
| 2, 9, 23, 26 | Timestomp, raw read, file delete | planned: minifilter (#136) |
| 8 | Remote thread | planned: #137; candidate without a driver: a Kernel-Process thread start whose creating process is not the target (unverified) |
| 10 | Process access (LSASS) | planned: #137; candidate without a driver: Microsoft-Windows-Kernel-Audit-API-Calls `OpenProcess` (task 5: `TargetProcessId`, `DesiredAccess`, [Elastic][elastic]) (unverified) |
| 4, 16, 255 | Sysmon service state changed, configuration changed, error | none |
| 17, 18 | Named pipe created, connected | none |
| 25 | Process tampering (hollowing, herpaderping) | none |

The two candidates for 8 and 10 are ETW providers a user-mode consumer can enable, unlike
TI-ETW (which needs a PPL) and `ObRegisterCallbacks` (which needs a driver). Whether they
deliver those fields to our session, and at what volume, is a lab question this ADR does
not answer; it only refuses to fill with Sysmon a gap we may be able to close ourselves.

## Decision

Consume Sysmon, **as a gap filler and never as an aggregator**.

1. **Do we consume it at all?** Yes, but only the events we cannot collect natively.
   Sysmon is not a prerequisite of any shipped detection and never replaces a native
   source. When a native collector ships, the Sysmon events it replaces leave the
   allowlist in the same release: 2, 9, 15, 23 and 26 with the minifilter (#136), 8 and
   10 with whichever of #137 or the driver-free candidates above ships first.
2. **Opt-in or auto-detected?** Opt-in, off by default, in `agent.toml`
   (`[windows] sysmon = false`). `true` subscribes when the channel exists and is enabled,
   and otherwise logs once and does nothing. This adds a `[windows]` section to the
   ADR-0013 schema, whose loader refuses unknown fields, so it is an amendment of that
   schema, not a free addition. The agent never installs, enables, updates or configures
   Sysmon, and never writes its configuration: that is the operator's, and a security
   agent that rewrites another security tool's filters is a liability.
3. **Duplication with native ETW?** Avoided by construction rather than deduplicated: the
   subscription query names only the allowlisted event ids, which have no native
   equivalent at the time of the release. No correlator dedup logic is written, because
   no event arrives twice. Events keep their own schema variants with `source` carried by
   the variant, not a flag on a shared one. The first allowlist:
   - **Kept while Sysmon is consumed at all:** 4, 16, 17, 18, 25 and 255.
   - **Until #136 ships:** 2, 9, 23, 26, and 15 except `Zone.Identifier` streams, which the
     parser drops because #365 and #442 already report them.
   - **8 and 10 only if the lab capture (follow-up 1) shows the driver-free candidates do
     not work.** If they work, they ship as native ETW collection and 8 and 10 never enter
     the allowlist.

   Whatever enters is bounded and observable, like all detection input: a per-id filter
   before normalization (for 10, accesses to LSASS with a memory-reading `GrantedAccess`
   only) and a per-id rate cap with counted shedding on the ADR-0006 channel counters, so
   one host with an unfiltered Sysmon configuration cannot flood the sink.
4. **Which versions?** A tolerant parser keyed by numeric event id and field *name* (the
   approach #283 took for the localized Defender channel), ignoring unknown fields.
   Golden fixtures are captured from the current Sysinternals release and from the
   Windows-native build, on a real host. Older releases are best effort and untested; the
   supported set is stated in the docs and moves with the fixtures. The fields are
   strings written by whatever ran on the host (command lines, pipe names, image paths),
   which may be compromised, so the parser gets a never-panic robustness suite in its
   crate's `tests/` and a fuzz target in `fuzz/` for the record and field parsing.
5. **An operator configuration that filters out what we expect?** We cannot see a filter,
   so we make silence visible instead of assuming. The channel gets a liveness heartbeat
   and a per-event-id last-seen counter like the other eventlog targets, and the health
   output reports "Sysmon enabled, no event 10 seen in N hours". A rule that needs Sysmon
   data declares it, and a missing source is reported as a degraded detection, not as
   "no findings". Sysmon tampering is itself a finding (T1562.001), the one Sysmon signal
   worth having even for an operator who relies on native collection alone: a service
   stop (EID 4), a configuration change (EID 16) or an error (EID 255). A Sysmon that is
   killed or whose driver is unloaded cannot be trusted to report it, so the rule also
   uses the channel's silence and native signals (the exec of `fltmc unload`, `sc stop`,
   `sysmon -u`). It keys on the channel and event ids, never on the default
   `Sysmon64`/`SysmonDrv` names, which the operator can change at install (`-d`).

Separately, and not part of this decision: widening `crates/sigma` so `logsource`
categories map onto native events and the usual field names resolve. That, not Sysmon, is
what opens the public rule catalogue. It gets its own issue and, if it needs one, its own
ADR.

## Consequences

- The Windows sensor gains one opt-in channel with a short, explained allowlist, instead of
  an open-ended second event pipeline. The work is small and bounded.
- Hosts with Sysmon get named-pipe and process-tampering visibility, and file-level events
  *before* the minifilter (#136) lands, and lose nothing when it does. Process access and
  remote threads come from Sysmon only if the driver-free native candidates fail the lab
  check.
- A deployment that never enables Sysmon is unaffected: same events, same volume.
- We take on a parser per Sysmon event id, its robustness suite and fuzz target, and a
  fixture set per supported release, and the native-Sysmon schema is unknown until
  captured. The first implementation step is a lab capture, not code.
- The "EDR or Sysmon aggregator" question is settled in favour of the EDR: native
  collection stays the product, Sysmon fills named gaps and is retired from each as the
  native source replaces it.
- The allowlist and its shrinking are a maintenance commitment each time #136, #137 or a
  driver-free native source ships.

## Alternatives considered

- **Reject: do not consume Sysmon.** Simplest, and consistent with the native-first vision.
  Gives up named-pipe, process-tampering and early file events on every Sysmon host, and
  Sysmon tamper detection. Reasonable if the team prefers to keep the sensor surface
  minimal; the cost is a visibility gap we already know about.
- **Aggregate: consume every Sysmon event as a first-class source.** Adds the duplication
  problem the issue describes (each process and connection twice) for no visibility we do
  not already have, and makes correlation depend on an optional tool. Rejected.
- **Auto-enable when Sysmon is detected.** Turns on a second pipeline on hosts whose
  operator did not ask for it, and changes event volume after a Sysmon install. Rejected
  for opt-in.
- **Take 8 and 10 from Sysmon now, retire them with #137.** The highest-value ids, but
  also the noisiest, and #137 needs a driver and a PPL that are long-term (#39). Rejected
  until the driver-free candidates are tested: if they work, Sysmon would only have
  delayed native collection.

## Follow-up issues (to open now that this is accepted)

1. Lab capture of the Sysmon channel on a Sysinternals install and on a Windows-native
   build: channel name, event schema, volumes, the event ids of the allowlist. In the same
   capture, the two driver-free candidates for 8 and 10 (Kernel-Process thread start,
   Kernel-Audit-API-Calls `OpenProcess`): whether our non-PPL session receives them, with
   which fields, at what volume on an idle and a busy host.
2. `sysmon` configuration switch (the ADR-0013 schema amendment), subscription target,
   heartbeat, per-id counters, per-id filters and rate caps with counted shedding.
3. Schema variants and parsers for the allowlisted event ids, with golden fixtures, a
   never-panic robustness suite and a fuzz target.
4. Sysmon tamper rule (EIDs 4, 16, 255, channel silence, native stop and unload
   signals), T1562.001.
5. `crates/sigma`: `logsource` category mapping and field mapping onto native events.
6. If follow-up 1 confirms them: native remote-thread and LSASS-access collection from
   the driver-free providers, filed against #137.

[ms]: https://techcommunity.microsoft.com/blog/windows-itpro-blog/-/4468112
[petri]: https://petri.com/microsoft-native-sysmon-windows-11/
[techzine]: https://techzine.eu/news/security/138521/windows-11-gets-built-in-sysmon-for-security-detection
[elastic]: https://www.elastic.co/security-labs/blog/kernel-etw-best-etw
