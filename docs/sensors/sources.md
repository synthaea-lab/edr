# Telemetry Source Inventory

What the agent can observe, organized to answer two questions in order:

1. **What kind of information do we get?** — the coverage tables lead with the
   signal domain (process, file, network, memory, identity, …). All three
   platforms use the same domain list in the same order, so cross-platform
   parity is readable at a glance: a domain `used` on one platform and
   `planned` or `gap` on another is exactly the coverage difference.
2. **Where does it come from?** — each platform first lists its **master
   sources** (ETW, `EndpointSecurity`, eBPF, …) once, with cost/privilege and
   the empirical findings stated there instead of repeated per row; the
   coverage rows then reference a master by name (`ETW · Kernel-Process`), so
   everything one master delivers groups visually.

Status of a row: **used** (code on `main`), **built** (code on `main`, runtime
prerequisite outstanding), **planned** (issue filed), **gap** (no mechanism
evaluated yet — named so it stays a visible decision), **rejected** (per
platform, where the reason is the row). MITRE tags are the techniques as
actually tagged in `crates/rules`/`correlator`, not aspirational mappings.


## Coverage at a glance

One cell per platform and signal domain: the status glyph plus the master
source that delivers (or will deliver) it. Each focus names the ATT&CK
tactics it chiefly feeds — the technique-level view lives in
[docs/detection/attack-coverage.md](../detection/attack-coverage.md). The
per-platform tables below carry the detail behind every cell.

**Legend:** ✅ used · 🔨 built (runtime prerequisite outstanding) ·
📋 planned (issue filed) · 🔍 evaluated (matrix) · ⭕ gap (no mechanism
evaluated yet) · — not applicable · 🟡\* telemetry lands, detection content
pending (the coverage packs #376–#381 — see
[attack-coverage.md](../detection/attack-coverage.md))

| Focus | Linux | Windows | macOS |
| --- | --- | --- | --- |
| **Process execution**<br><sub>TA0002 Execution</sub> | ✅ eBPF (+netlink fallback) | ✅ ETW | ✅ ES |
| **File activity**<br><sub>TA0040 Impact · TA0005 Evasion</sub> | ✅ eBPF + BPF-LSM | ✅ ETW · 📋 driver #136 | ✅ ES · 📋 #357 |
| **Network — flows & listeners**<br><sub>TA0011 C2 · TA0008 Lateral</sub> | ✅ eBPF + netlink | ✅ ETW · ✅ IP Helper listen | 🔨 NE · ✅ libproc listen |
| **Mounts & volumes**<br><sub>staging · TA0005 Evasion</sub> | 📋 #362 | 📋 #136 raw-volume | ✅ ES |
| **DNS**<br><sub>TA0011 C2</sub> | 📋 #267 | ✅ ETW | 🔨 NE |
| **Lateral-movement services**<br><sub>TA0008</sub> | 🟡* SSH-out content | ✅ SMB + WMI · 📋 #284 BITS | 🟡* SSH-out content |
| **Encrypted traffic**<br><sub>TA0011 C2 · TA0010 Exfil</sub> | ✅ uprobes · 📋 JA4 #86 | 📋 #373 | 📋 #360 |
| **Scripts & shells**<br><sub>TA0002 Execution</sub> | ✅ uprobes | ✅ ETW · 📋 AMSI #282 | 📋 #374 (evaluate) |
| **Memory & injection**<br><sub>TA0005 Evasion · TA0004 Priv-Esc</sub> | 📋 #265 | 📋 driver #137 | 📋 #355 |
| **Logons & sessions**<br><sub>TA0001 Valid Accounts · TA0008</sub> | ✅ journald | ✅ WEL · 📋 #285 RDP | ✅ ES + log |
| **Privilege elevation**<br><sub>TA0004 Priv-Esc</sub> | 🟡* sudo via journald · 📋 #266 setuid | 🟡* UAC content | ✅ sudo · 📋 #356 native |
| **Credential-attack shadow**<br><sub>TA0006 Cred Access</sub> | 🟡* shadow-file reads | 📋 #364 Kerberos/NTLM/LDAP | 🟡* keychain reads |
| **Account management**<br><sub>TA0003 T1136</sub> | 🟡* useradd content | ✅ WEL 4720 | 📋 #356 OD events |
| **Services & autostart**<br><sub>TA0003 T1543/T1547</sub> | ✅ journald + rules | ✅ WEL 7045 + ETW registry | ✅ ES BTM |
| **Scheduled execution**<br><sub>TA0002/TA0003 T1053</sub> | ✅ cron/systemd paths | ✅ WEL 4698 · 4702 | ✅ cron/launchd paths |
| **OS security verdicts**<br><sub>TA0005 Evasion context</sub> | 🔍 SELinux AVC | 📋 #283 | ✅ log · 📋 #356 |
| **Kernel modules & drivers**<br><sub>TA0003/TA0005 rootkits</sub> | 📋 #264 module+bpf | 🟡* image loads · 📋 #39 | 📋 #357 kexts |
| **Tamper on security tooling**<br><sub>TA0005 T1562</sub> | 📋 #362 kill-trace | 📋 #39 driver vantage | ✅ ES signals |
| **Anti-forensics**<br><sub>TA0005 T1070</sub> | 🟡* deletions · LSM timestomp row | 📋 #136 timestomp/ADS | ✅ deletions · 📋 #357 strip/stomp |
| **Download provenance**<br><sub>TA0001 Initial Access</sub> | 📋 #87 (no OS mark) | ✅ ETW MotW | ✅ ES |
| **Devices**<br><sub>TA0001 Initial Access · TA0010 Exfil</sub> | 📋 #84 | 📋 #84 | 📋 device-control |
| **Containers**<br><sub>TA0004 Escape context</sub> | ✅ /proc | 📋 #371 silos | 📋 #372 host-side |
| **Host state & inventory**<br><sub>TA0003 pre-existing persistence</sub> | 📋 #87 | ✅ WMI · 📋 #286 | 📋 #359 |

## Linux

See [linux-telemetry-matrix.md](linux-telemetry-matrix.md) for the full
hook/fields/overhead/kernel/OSS-comparison detail behind each mechanism,
including the evaluated-but-not-implemented tier (fanotify, fentry, SELinux
AVC, seccomp, …) and the SELinux-on-server validation gap.

### Master sources

| Source | Mechanism | Cost & privilege (as observed) |
| --- | --- | --- |
| **eBPF** | tracepoints, uprobes, BPF-LSM hooks — ring buffers, in-kernel filters | Low overhead. Root or `CAP_BPF`+`CAP_PERFMON`; 5.10+ practically (CO-RE), LSM 5.7+. Capability probed at startup, never a hardcoded version |
| **netlink** | `sock_diag`, conntrack, proc connector, `NETLINK_AUDIT` multicast | Low (10s polls). `sock_diag` confirmed **unprivileged** empirically; proc connector root-only (`EPERM`); audit needs `CAP_AUDIT_READ`. Audit is the designated eBPF fallback — degraded, honest (`parent_lineage: false`) |
| **journald** | `journalctl -f -o json` subprocess tail, allowlist-first | Medium (subprocess + JSON per line). Root in practice — journald's per-unit read ACL blocks unprivileged auth reads (empirical) |
| **/proc, /sys** | event-triggered reads + startup seeding — never a /proc-wide poll loop | Low; mostly unprivileged |
| **device-control** | udev/uevent netlink device notifications | Planned (#84); root for the uevent socket |
| **inventory** | scheduled state snapshots, diffed | Snapshot cadence, not events |

### Signal coverage

| Focus | Source | What we get | Status | MITRE | Issue |
| --- | --- | --- | --- | --- | --- |
| **Process execution** | eBPF · tracepoints | exec/fork/exit with argv, comm, uid/gid, lineage | ✅ used | T1059 | #262 |
| **Process execution** | netlink · audit | fallback exec + connect where eBPF is unavailable (lockdown, old kernel) | ✅ used | T1059 degraded | #34/#247 |
| **Process execution** | procfs · `/proc/<pid>/environ` at exec-time drain | security-relevant exec environment (`LD_PRELOAD` family), present-only allowlist — never the whole env | ✅ used | T1574.006 | #363 |
| **File activity** | eBPF · tracepoints | open/write/delete/rename/chmod/chown with paths + attribution; noisy /dev,/proc,/sys,/tmp filtered | ✅ used | T1105, T1485/T1486, T1070.004, T1222 | #262 |
| **File activity** | eBPF · BPF-LSM | `file_open` at the security decision point — deliberate double observation (blinding check), io_uring-proof vantage; inline-block ready | ✅ used | T1562 context | #91 |
| **File activity** | eBPF · BPF-LSM | timestomping via `inode_setattr` hook | 📋 planned | T1070.006 | matrix row |
| **Network** | eBPF · tracepoints | connect/bind/listen/accept, UDP sends — discrete, real-time | ✅ used | T1071/T1041, backdoor listeners | #263 |
| **Network** | netlink · sock_diag+conntrack | listening-port snapshots (LISTENER-DRIFT), flow 5-tuples + byte counters | ✅ used | beacon volume features | #92 |
| **Network** | eBPF · tracepoints | mount/umount → platform-neutral v21 `Mount` | 📋 planned | staging, evidence destruction | #362 |
| **DNS** | eBPF | query/answer joined to the resolving process (udp:53 parse vs. `getaddrinfo` uprobe — choice in-issue) | 📋 planned | T1071.004, DGA features | #267 |
| **Encrypted traffic** | eBPF · uprobes | TLS plaintext pre-encryption/post-decryption (OpenSSL/BoringSSL/GnuTLS), byte-budgeted + redacted | ✅ used | T1071 C2 visibility without MITM | #90 |
| **Encrypted traffic** | eBPF | JA4 fingerprint + SNI on connects | 📋 planned | C2 tooling fingerprints | #86 |
| **Scripts & shells** | eBPF · uprobes | interactive shell input (readline) incl. builtins that never exec | ✅ used | T1059 | #90 |
| **Memory & injection** | eBPF · tracepoints | ptrace ops, `process_vm_*`, `/proc/*/mem` writes, `memfd_create`+exec (fileless) | 📋 planned | T1055, T1620 | #265 |
| **Identity & privilege** | journald | sshd accept/fail, PAM sessions, sudo/su → `Auth` | ✅ used | T1078 | #93 |
| **Identity & privilege** | eBPF · tracepoints | `setuid`/`setresuid`/`capset`/`setns` | 📋 planned | T1548, container escape | #266 |
| **Persistence & autostart** | journald + rules | systemd unit first-start (flagged approximation, documented); rc/cron/systemd path writes via the file stream | ✅ used | T1543.002, T1053.003 | #93 |
| **OS security verdicts** | netlink · audit | SELinux AVC denials — already on the socket, one classifier arm away | 🔍 evaluated | T1562-adjacent | matrix row |
| **Tamper & anti-forensics** | eBPF · tracepoints | module loads/unloads, `bpf(2)` loads (eBPF-rootkit visibility) | 📋 planned | T1547.006, T1562 | #264 |
| **Tamper & anti-forensics** | eBPF · tracepoints | kernel-side kill tracing filtered to agent/security targets — SIGKILL **sender** attribution userspace cannot see → v21 `Signal` | 📋 planned | T1562 | #362 |
| **Download provenance** | inventory | no OS-level mark on Linux — browser artifacts only | 📋 planned | provenance context | #87 |
| **Devices** | device-control | USB attach/detach + policy | 📋 planned | T1091, T1052 | #84 |
| **Containers** | /proc | cgroup → container-id attribution on every event | ✅ used | container context for all rules | #80 |
| **Host state** | inventory | diffed snapshots (packages, units, cron) — persistence that predates the agent | 📋 planned | | #87 |

### Rejected

| Mechanism | Why |
| --- | --- |
| custom kernel module | eBPF-only stance: verifier safety, no third-party kernel code |
| ptrace interception | invasive, single-tracer conflicts, evasion tarpit |
| perf hardware counters | rejected (revisit) — niche side-channel detections; cost/benefit unproven |
| AF_PACKET / libpcap full capture | volume without need — conntrack flows (#92) + JA4/SNI (#86) carry the network signal; TLS content is cheaper pre-encryption via uprobes (#90) |
| inotify | coarser than the eBPF file events and fanotify (#34); no process attribution |
| utmp/wtmp/btmp parsing | journald (#93) carries the same logins with provenance |

## Windows

### Master sources

| Source | Mechanism | Cost & privilege (as observed) |
| --- | --- | --- |
| **ETW** | one kernel-provider session, nine manifest-based providers | Administrator. Session name randomized per start, persisted for orphan cleanup, silence watchdog turns a stopped trace into a loud error (F-2) |
| **WEL** (Windows Event Log) | channel polling via `wevtutil` (2s) | Administrator for the Security channel. Lab-earned (ADR-0004): 7045's classic provider defeats TDH schema resolution, and the Security channel never delivered to an ad-hoc raw-ETW subscriber — `EvtSubscribe` is the evaluated successor. Per-channel allowlist + volume counters (ADR-0006) |
| **driver tier** | kernel callbacks, minifilter, WFP, Threat-Intelligence ETW | Signed driver, its own distribution tier; TI-ETW additionally needs PPL. All planned (#39) |
| **Win32 APIs** | table snapshots (`GetExtendedTcpTable`), WMI/CIM queries | Unprivileged; snapshot cadence |
| **device-control** | PnP/device-interface notifications | Planned (#84, cross-platform crate) |

### Signal coverage

| Focus | Source | What we get | Status | MITRE | Issue |
| --- | --- | --- | --- | --- | --- |
| **Process execution** | ETW · Kernel-Process | exec with the **real** PEB command line (F-1), per-event SID + integrity level (F-3), lineage | ✅ used | T1059 | #20 |
| **Process execution** | ETW · Kernel-Process | image/DLL loads (EID 5) | ✅ used | T1574.002 side-loading | #21 |
| **File activity** | ETW · Kernel-File | create/write (`NameCreate`+`CreateNewFile` join, F-6 partial), NT→drive-letter paths via real volume map (F-5) | ✅ used | T1105, dropper joins | #20 |
| **File activity** | driver · minifilter | authoritative deletes/renames, named pipes, ADS, raw-volume access | 📋 planned | ransomware primitives | #136 |
| **Network** | ETW · Kernel-Network | TCP connects (IPv4+IPv6 first-class F-7, dedup window), UDP sends (EID 14) | ✅ used | T1071/T1041 BEACON, T1048 | #20/#97 |
| **Network** | Win32 · GetExtendedTcpTable | listening-port snapshots (IPv4 + IPv6, 10s) + startup baseline — LISTENER-DRIFT parity with Linux/macOS; unprivileged, owner pid/ppid/name via Toolhelp32 | ✅ used | backdoor listeners | #366 |
| **Network** | ETW · SMBClient | SMB connections established (EID 30704; failures dropped) | ✅ used | T1021.002 | #97 |
| **Network** | driver · WFP | flows + inline block | 📋 planned | response primitive | #138 |
| **DNS** | ETW · DNS-Client | query + answer + status joined to the process (EID 3008; 3006 dropped as noise) | ✅ used | T1071.004, IOC join | #21 |
| **Encrypted traffic** | ETW + driver · WFP | TLS handshake metadata (evaluate Schannel providers); JA4 + SNI via #138's callout for cross-platform fingerprint parity — plaintext has no supported analog, stated honestly | 📋 planned | T1071 fingerprints | #373 |
| **Scripts & runtimes** | ETW · PowerShell | script blocks (EID 4104) **post-decode** — `-EncodedCommand` arrives plain, fragments reassembled | ✅ used | T1059.001, T1027 | #21 |
| **Scripts & runtimes** | ETW · AMSI | script/VBS/JS content at the scan interface | 📋 planned | T1059, T1027 | #282 |
| **Scripts & runtimes** | ETW · DotNETRuntime | **dynamic (in-memory) assembly loads only** (EID 154, `flags & 0x2`) — file-backed dropped at the sensor | ✅ used | T1620, T1055 | #97 |
| **Memory & injection** | driver · ObCallbacks+TI-ETW | handle access to LSASS; injection telemetry | 📋 planned | T1003.001, T1055 | #137 |
| **Identity & privilege** | WEL · Security | logons 4624/4625/4648/4672 → `Auth` | ✅ used | T1078, T1110 | #94 |
| **Identity & privilege** | ETW · Kerberos/NTLM/LDAP-Client | client-side ticket requests (RC4-etype shadow), NTLM validation, LDAP recon bursts — DC-side 4768/4769 stay server scope, honestly | 📋 planned | T1558, AD recon | #364 |
| **Identity & privilege** | WEL · TerminalServices | RDP session lifecycle | 📋 planned | T1021.001 | #285 |
| **Persistence & autostart** | WEL · System+Security | service install 7045, scheduled task 4698 + update 4702 (task hijack, path-gated), local account 4720 — flag-gated deterministic events | ✅ used | T1543.003, T1053.005, T1136.001 | #94 |
| **Persistence & autostart** | ETW · Kernel-Registry | value writes (EID 4, NT→`HKLM` normalized; reads deliberately not taken) | ✅ used | T1547.001, T1112 | #21 |
| **Persistence & autostart** | driver · kernel callbacks | process/image/registry from the tamper-resistant vantage | 📋 planned | same, authoritative | #39 |
| **OS security verdicts** | WEL · operational channels | AppLocker, WDAC, Defender, Task-Scheduler | 📋 planned | policy + AV context | #283 |
| **Lateral-movement services** | ETW · WMI-Activity | WQL queries (EID 23) + method invocations (EID 24, `Win32_Process.Create`) | ✅ used | T1047 | #21 |
| **Lateral-movement services** | ETW · BITS-Client | background transfer jobs | 📋 planned | T1197 | #284 |
| **Tamper & anti-forensics** | driver · minifilter | timestomping (SetInformation), ADS manipulation, raw-volume access | 📋 planned | T1070.006, T1564.004 | #136 |
| **Download provenance** | ETW · Kernel-File | `Zone.Identifier` ADS write (mark-of-the-web) → v21 `FileQuarantine` (`HostUrl`/`ReferrerUrl` read-back, writer as `agent`; zones 0–2 dropped; a raced read reports the mark alone); consumed by the T1204.002 download→exec join. Strip/tamper of the mark needs the minifilter (#136) | ✅ used | T1204.002 | #365 |
| **Containers** | Win32 · silo query | server-silo attribution on process-isolated Windows containers → `EventMeta::container` (Hyper-V/WSL2 = agent-inside, documented) | 📋 planned | container context for rules | #371 |
| **Devices** | device-control | Windows collectors land with the cross-platform crate | 📋 planned | T1091 | #84 |
| **Host state** | Win32 · WMI/CIM | point-in-time inventory; Sysmon-channel opt-in is an ADR-first decision | ✅ / 📋 | pre-existing persistence | collectors; #286 |

### Rejected

| Mechanism | Why |
| --- | --- |
| Userland API hooking / detours | stability, AV conflicts, trivially unhookable — ETW + kernel callbacks only |
| Clipboard capture | privacy/noise cost exceeds detection value; commercial norm agrees |
| Raw packet capture (WinPcap/npcap-style) | ETW network + WFP (#138) carry the signal without the driver and volume cost |
| Keystroke / screen capture | privacy line, same reasoning as clipboard |
| Execution-history artifacts (Prefetch, Amcache, Shimcache) | rejected (deferred) — point-in-time forensics, not streaming telemetry; DFIR workbench territory (M10), pulled on demand |
| WMI event watchers as a telemetry source (`Win32_ProcessStartTrace` & co.) | the pre-ETW era's mechanism — polling latency and provider gaps; ETW supersedes it wholesale (watching *attackers'* WMI subscriptions stays in scope via #21/inventory) |

## macOS

### Master sources

| Source | Mechanism | Cost & privilege (as observed) |
| --- | --- | --- |
| **ES** (`EndpointSecurity`) | one entitled client, NOTIFY-only subscriptions flattened through a C shim compiled against the SDK's own headers | Root + ES entitlement + Full Disk Access. **Live-verified**: amfid SIGKILLs an ad-hoc restricted entitlement at exec (error -424), before TCC — Apple grant or SIP+AMFI-relaxed lab only. Self-muted against feedback; per-family OS-version guards. AUTH (blocking) is M6 |
| **unified log** | `log stream --style ndjson` under a strict predicate; three volume gates (daemon predicate → exact-message classifier → counted sliding-window shed) | Admin scope. Formats undocumented by Apple — pinned by verbatim live-capture tests, the OS-update tripwire. Live-validated end to end |
| **NE** (`NetworkExtension`) | Swift system extension (filter-data + DNS-proxy providers) → versioned NDJSON over an app-group socket to the agent | Restricted entitlements + user/MDM approval (`packaging/macos`); wire skew counted, never guessed. Seam + typed scaffold on `main`; activation outstanding (#351) |
| **libproc** | socket-table snapshots via a C shim against the SDK headers (`sensors/macos/sockets`) | Unprivileged — works before any Apple grant; root widens visibility to all users' processes |
| **DiskArbitration / IOKit** | disk + device attach/detach notifications | Planned (`device-control`); unprivileged for notifications |
| **inventory** | scheduled state snapshots | FDA for the TCC.db snapshot |

### Signal coverage

| Focus | Source | What we get | Status | MITRE | Issue |
| --- | --- | --- | --- | --- | --- |
| **Process execution** | ES · exec | argv + the kernel's code-signing state at the source (`CS_VALID`, signing/team id, platform-binary bit), lineage | ✅ used | T1059, unsigned-binary-ran | #32 |
| **File activity** | ES · file events | open/create/rename/unlink; mmap **filtered to writable+shared** (dyld torrent dropped in-shim); POSIX `O_*` flags so cross-platform write rules apply unchanged | ✅ used | T1105, T1485/T1486, T1070.004 | #32 |
| **File activity** | ES · widening | quarantine **strip**, timestomp, hidden flags, APFS clone/exchangedata staging, remount | 📋 planned | T1070.006, T1564.001 | #357 |
| **Network** | NE · filter-data | flows with audit-token attribution (inbound + outbound) → `Connect`, close-time byte counts → `NetworkFlow` — BEACON consumes macOS flows unchanged | 🔨 built | T1071/T1041 | #33/#351 |
| **Network** | libproc/sysctl | listening-port snapshots + baseline — the one source needing **no entitlement** | 📋 planned | LISTENER-DRIFT parity | #358 |
| **Network** | ES · mount | mount/unmount (DMG delivery, USB staging) → v21 `Mount` | ✅ used | staging, evidence destruction | #96 |
| **DNS** | NE · DNS-proxy | proxied query/response with process attribution → `DnsQuery` (RCODE in `status`) | 🔨 built | T1071.004, domain↔process join | #33/#351 |
| **Encrypted traffic** | NE · filter-data | TLS ClientHello peek → SNI + JA4 (Linux #86 parity) | 📋 planned | C2 fingerprints | #360 |
| **Scripts & shells** | evaluation | interactive-shell parity with Linux #90: survey supported mechanisms, decide, record used-or-rejected in this inventory | 📋 planned | T1059 | #374 |
| **Memory & injection** | ES · widening | task-port acquisition, ptrace, remote thread creation, CS invalidation, suspend/resume, RWX mprotect, pty — the coverage-matrix promise #32/#96 only partially landed | 📋 planned | T1055, T1562 | #355 |
| **Identity & privilege** | ES · sessions | SSH/console/loginwindow logins → `Auth` (13+) | ✅ used | T1078 | #96 |
| **Identity & privilege** | unified log · sudo | sudo outcomes → `Auth`; ES-native su/sudo supersedes on 14+ | ✅ / 📋 | T1548.003 | #95; #356 |
| **Persistence & autostart** | ES · BTM | launch-item registration — deterministic, the macOS 7045 (payload path + instigator); launchd/cron path writes via the file stream | ✅ used | T1543.001/.004, T1547.015 | #32 |
| **Persistence & autostart** | ES · widening | Open Directory account manipulation, configuration-profile installs (14+) | 📋 planned | T1136.001 | #356 |
| **OS security verdicts** | unified log · syspolicyd+tccd | Gatekeeper scan verdicts (Mach-O only — scripts log `performScan` without a verdict, observed live); TCC grant/deny joined on tccd's msgID (client redacted → #354) | ✅ used | delivery context, TCC-probing recon | #95 |
| **OS security verdicts** | ES · widening | XProtect malware verdicts, Gatekeeper **user override**, native TCC modify with client identity (15.4+) | 📋 planned | OS's own AV verdict for free | #356 |
| **Tamper & anti-forensics** | ES · signal | signals **filtered to ES-client targets** (this agent, other security tools), sender attributed | ✅ used | T1562 | #96 |
| **Tamper & anti-forensics** | ES · widening | kext loads, sensitive IOKit user-client opens | 📋 planned | T1547.006, keylogger preludes | #357 |
| **Tamper & anti-forensics** | ES · XPC | XPC connects (14+) — rules match sensitive service names, never per-event | ✅ used | agent-impersonation surface | #96 |
| **Download provenance** | ES · quarantine | quarantine xattr + `kMDItemWhereFroms` read-back → v21 `FileQuarantine` (agent, origin + referrer URLs) — the network→file link | ✅ used | provenance | #96 |
| **Containers** | inventory + ES/NE | runtime/VM inventory (Docker Desktop, OrbStack, Apple Containerization) + tagging of VM-manager processes/flows the sensors already see; in-VM Linux workloads = the Linux agent's job, documented | 📋 planned | unmanaged-workload signal | #372 |
| **Devices** | DiskArbitration/IOKit | disk/volume + device attach/detach | 📋 planned | T1091, T1052 | `device-control` |
| **Host state** | inventory | pre-existing launch items, kexts/system extensions, profiles, the standing TCC-grant map, browser artifacts | 📋 planned | persistence that predates the agent | #359 |

### Rejected

| Mechanism | Why |
| --- | --- |
| ES read-side metadata events (stat, lookup, getattrlist, readdir, access, …) | pure volume without mutation — nothing a detection keys on that the write-side events don't already carry |
| NetworkExtension packet-tunnel provider | rejected (revisit) — full-packet capture is cost without need given filter-data + DNS |
| kexts / kauth | deprecated and disallowed by Apple |
| openbsm audit trail | deprecated; ES supersedes |
| FSEvents | coarser than ES file events; no attribution |
| DTrace | requires SIP disabled — a dev-machine tool by construction, not deployable telemetry |
| ASL / legacy syslog | superseded by the unified log (#95 reads the successor) |

Cross-platform note: download provenance is one shape on all three platforms —
Windows mark-of-the-web (shipped, #365), the macOS quarantine xattr (shipped, #96), and
browser artifacts via `inventory` — all feeding the platform-neutral
`FileQuarantine` event: the provenance link between a network event and a
dropped file.
