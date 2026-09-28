# ATT&CK Coverage Assessment

Hand-written snapshot (assessed 2026-09-22) of MITRE ATT&CK Enterprise
coverage: which techniques the agent **detects** today, which it merely
**sees**, which wait on planned telemetry, and which are out of scope with a
reason. This is the manual predecessor of #74's generated matrix (structured
technique fields on `Detection` + a `tools/attack-coverage` generator); once
that lands, this file is replaced by generated output and never hand-edited
again.

Two layers of honesty this table enforces:

- **Detected ≠ visible.** A 🟢 means named detection content exists (a rule,
  a correlator chain, a flagged event a rule consumes). A 🟡 means the
  telemetry lands in the pipeline — the ML scorer and correlator see it — but
  no content names the technique. Turning 🟡 into 🟢 is *content* work
  (M5), tracked by the coverage-pack issues below.
- **Endpoint scope.** ATT&CK Enterprise includes cloud/SaaS/identity-provider
  techniques (Cloud Accounts, Email Collection via M365, …) an endpoint agent
  never observes; those are the plane's integrations territory (M9/M10) and
  are listed once under "Out of endpoint scope", not per tactic.

**Legend:** 🟢 detection content on-device · 🟡 telemetry visible, no
dedicated content · 📋 waits on a filed issue (telemetry or content) ·
⚪ assessed, out of scope here — with per-platform triplets **L**inux /
**W**indows / **M**acos where coverage differs.

Engine tags as of this assessment (from `rules`/`correlator` source):
T1021.002, T1036.005, T1037.004, T1041, T1048.003, T1053.003/.005, T1055,
T1059 (+.001/.004), T1070.002, T1071 (+.004), T1105, T1110, T1127, T1136.001,
T1204, T1218, T1486, T1490, T1543.001/.002/.003, T1547.015, T1571, T1574.006, T1611, T1620. Sigma-imported content carries its
own tags (pipeline: #73); YARA/intel content is #60/#82 territory.

## Initial Access (TA0001)

| Technique | L | W | M | Status / what closes it |
| --- | --- | --- | --- | --- |
| T1566 Phishing (attachment/link → execution) | 🟡 | 🟢 | 🟢 | Provenance→exec join (T1204.002) on `FileQuarantine`: macOS xattr (#96), Windows MotW (#365); Linux has no OS mark (browser artifacts #87). Content: pack issue below |
| T1189 Drive-by Compromise | 🟡 | 🟡 | 🟡 | Browser-lineage exec rules exist (download-then-exec); naming the technique is content work |
| T1078 Valid Accounts | 🟡 | 🟡 | 🟡 | `Auth` events on all three platforms; anomaly content (impossible travel is plane-side M9) |
| T1190 Exploit Public-Facing App | 🟢 | 🟡 | 🟡 | Linux web-server-lineage rule exists; W/M siblings are content work |

## Execution (TA0002)

| Technique | L | W | M | Status |
| --- | --- | --- | --- | --- |
| T1059 Command & Scripting Interpreter | 🟢 | 🟢 | 🟢 | Encoded-PowerShell (.001), base64-shell (.004), interpreter lineage; script blocks post-decode on W |
| T1204 User Execution | 🟢 | 🟢 | 🟢 | Download-then-exec chain tagged (L); T1204.002 provenance→exec join on `FileQuarantine` — Windows MotW (#365) and macOS quarantine xattr (#96) share one rule |
| T1047 WMI | — | 🟢 | — | `WmiActivity` events + tags live |
| T1053 Scheduled Task/Job | 🟢 | 🟢 | 🟡 | cron/systemd paths (L), 4698 + 4702 task hijack (W); macOS cron/launchd paths covered via persistence patterns |
| T1620 Reflective Code Loading | — | 🟢 | 📋 | Dynamic .NET loads tagged (W); macOS sibling in #355's set |

## Persistence (TA0003)

| Technique | L | W | M | Status |
| --- | --- | --- | --- | --- |
| T1543 Create/Modify System Process | 🟢 | 🟢 | 🟢 | systemd (.002), Windows service (.003), launchd (.001/.004 via BTM) — all flag-gated deterministic events |
| T1547 Boot/Logon Autostart | 🟡 | 🟢 | 🟢 | Run-key writes visible+rule'd (W), login items (.015, M); Linux rc-path patterns |
| T1053 Scheduled Task | 🟢 | 🟢 | 🟡 | as above |
| T1136 Create Account | 📋 | 🟢 | 📋 | 4720 (W) live; Linux useradd content work; macOS OD events #356 |
| T1546 Event-Triggered Execution | 🟡 | 🟡 | 🟡 | WMI subscriptions (W, via inventory #286-adjacent), shell-rc writes (L/M patterns partial) — pack below |
| T1574 Hijack Execution Flow | 🟢 | 🟡 | 🟡 | LD_PRELOAD/LD_AUDIT capture + trust-set rule #363 (L, lab: `ld-preload-hijack.sh`); DLL side-load visible via image loads (W); dylib content work (M) |

## Privilege Escalation (TA0004)

| Technique | L | W | M | Status |
| --- | --- | --- | --- | --- |
| T1548 Abuse Elevation Control | 📋 | 🟡 | 🟢 | sudo→`Auth` tagged (M via unified log; L journald visible); setuid/capset telemetry #266; UAC content work (W) |
| T1068 Exploit for Priv-Esc | 🟡 | 🟡 | 🟡 | Behavioral/ML territory by nature; kernel-surface tamper #264 helps L |
| T1611 Escape to Host | 🟢 | 📋 | — | Container proc-root rule (L); Windows silo context #371 first |

## Defense Evasion (TA0005)

| Technique | L | W | M | Status |
| --- | --- | --- | --- | --- |
| T1070 Indicator Removal (.002 log clearing shipped; timestomp pending) | 🟢 | 🟢/📋 | 🟢 | `check_log_clear_exec` (wevtutil/`log erase`/journal-vacuum, all platforms) + `check_log_file_delete` (L/M FileDelete streams; W file half waits on #136). Timestomp stays: LSM row (L), #136 (W), #357 (M) |
| T1562 Impair Defenses | 📋 | 📋 | 🟢 | Signal-to-ES-clients shipped (M); kill-tracing #362 (L); driver tamper telemetry #39 (W); service-stop content everywhere |
| T1055 Process Injection | 📋 | 🟢/📋 | 📋 | Remote-thread tag exists (W partial; full via TI-ETW #137); ptrace/process_vm #265 (L); task-port set #355 (M) |
| T1036 Masquerading | 🟢 | 🟢 | 🟢 | `check_masquerading` — system-binary names outside their legitimate locations (wave 1, #379) |
| T1027 Obfuscation | 🟢 | 🟢 | 🟡 | Encoded-command coverage; broader entropy scoring is the ML layer |
| T1553 Subvert Trust Controls | — | 📋 | 🟢/📋 | Gatekeeper override #356, quarantine-strip #357 (M); MotW-strip via #136 (W; #365 sees the mark written, not removed) |
| T1218 System Binary Proxy Execution | — | 🟢 | — | LOLBIN rule (W); L/M lolbin lists are content work |
| T1112 Modify Registry | — | 🟢 | — | Registry writes tagged via persistence rules |

## Credential Access (TA0006)

| Technique | L | W | M | Status |
| --- | --- | --- | --- | --- |
| T1003 OS Credential Dumping | 🟡 | 📋 | 🟡 | /etc/shadow reads visible (L), keychain-file reads visible (M) — content work; LSASS handle access needs ObCallbacks #137 (W) |
| T1110 Brute Force | 🟢 | 🟢 | 🟢 | AUTH-BURST sliding counter per (target, source) over the shared `Auth` stream (wave 1, #377) |
| T1555 Credentials from Password Stores | 🟡 | 🟡 | 🟡 | Browser-store/keychain file paths visible; content work |
| T1552 Unsecured Credentials (files) | 🟡 | 🟡 | 🟡 | File-open events + path/content heuristics; content work |
| T1558 Steal/Forge Kerberos Tickets | — | 📋 | — | Endpoint-side shadow via #364; DC-side is plane scope |
| T1056 Input Capture | ⚪ | ⚪ | ⚪ | We don't keylog (privacy line, inventory); *detecting* third-party keyloggers: IOKit-HID opens #357 (M), driver tier (W) |

## Discovery (TA0007)

| Technique | L | W | M | Status |
| --- | --- | --- | --- | --- |
| T1057 / T1082 / T1016 / T1087 recon (process/system/network/account) | 🟡 | 🟡 | 🟡 | All exec-visible; the signal is the *burst*, not one command — recon-burst content in the pack below |
| T1046 Network Service Discovery | 🟡 | 📋 | 📋 | Connect-fan-out visible (L); listener baselines #366/#358 sharpen it |
| T1518 Software Discovery (security tools) | 🟡 | 🟡 | 🟡 | Exec-visible; TCC-probing recon partially shipped via `TccDecision` (M) |
| T1069 Permission Groups Discovery | 🟡 | 📋 | 📋 | LDAP recon #364 (W); OD queries #356 (M) |

## Lateral Movement (TA0008)

| Technique | L | W | M | Status |
| --- | --- | --- | --- | --- |
| T1021.002 SMB/Admin Shares | — | 🟢 | — | Tagged |
| T1021.004 SSH | 🟡 | — | 🟡 | Inbound `Auth` shipped both; outbound-ssh-fan content work |
| T1021.001 RDP | — | 📋 | — | #285 |
| T1570 Lateral Tool Transfer | 🟡 | 🟡 | 🟡 | Write-then-exec joins exist per-host; cross-host is plane M9 |
| T1021.003 / T1047 DCOM & WMI | — | 🟢 | — | WMI method tags live |

## Collection (TA0009)

| Technique | L | W | M | Status |
| --- | --- | --- | --- | --- |
| T1005 Data from Local System / T1074 Staging | 🟡 | 🟡 | 🟡 | Read/write bursts + staging-dir patterns — content work (pack) |
| T1560 Archive Collected Data | 🟡 | 🟡 | 🟡 | archiver-exec + big-write joins; content work |
| T1113 Screen Capture / T1123 Audio | ⚪ | ⚪ | 🟢/🟡 | We don't capture; *detecting it*: TCC decisions (M, shipped) are exactly this signal; W/L content thin by platform nature |
| T1115 Clipboard | ⚪ | ⚪ | ⚪ | Rejected as telemetry (privacy); detection via API surface not available userland |

## Command & Control (TA0011)

| Technique | L | W | M | Status |
| --- | --- | --- | --- | --- |
| T1071 Application Layer Protocol | 🟢 | 🟢 | 🟢 | BEACON on all platforms (macOS via NE flows once #351 activates; 🔨 until then) |
| T1071.004 DNS | 📋 | 🟢 | 🔨 | #267 (L); DnsQuery live (W); NE DNS built (M) |
| T1573/T1571 Encrypted/Non-Standard Port | 🟢 | 🟡 | 🟡 | Non-standard-port tag (L); TLS fingerprints #86/#373/#360 deepen all three |
| T1105 Ingress Tool Transfer | 🟢 | 🟢 | 🟢 | Download-then-exec tagged |
| T1090/T1572 Proxy/Tunneling | 🟡 | 🟡 | 🟡 | Flow shapes visible; content work |

## Exfiltration (TA0010)

| Technique | L | W | M | Status |
| --- | --- | --- | --- | --- |
| T1041 Exfil over C2 | 🟢 | 🟡 | 🔨 | Volume features on flows (L conntrack; M NE byte counts); W flow-volume needs WFP #138 or per-connect heuristics |
| T1048 Exfil over Alternative Protocol | 🟢 | 🟡 | 🟡 | DNS-exfil tag exists (L); egress-volume content pack below |
| T1567 Exfil to Web Services | 🟡 | 🟡 | 🟡 | Domain+volume joins; content work |

## Impact (TA0040)

| Technique | L | W | M | Status |
| --- | --- | --- | --- | --- |
| T1486 Data Encrypted (ransomware) | 🟢 | 🟡 | 🟡 | Mass rename appending a suffix to the old path, per pid (20 in 5 s) and per parent for shell loops (L, #455); blind spots (in-place rewrite, rename to a new name, name-keyed FP gating) in #459; full pack is #82 (tripwires + reflex response) |
| T1490 Inhibit System Recovery | 🟢 | 🟢 | 🟢 | `check_recovery_inhibit` — vssadmin/wmic-shadowcopy/wbadmin/bcdedit/tmutil multi-token matches (wave 1, #381) |
| T1489 Service Stop | 🟡 | 🟡 | 🟡 | Unit/service lifecycle visible; content work |
| T1529 System Shutdown | 🟡 | 🟡 | 🟡 | Exec-visible; low value alone |

## Out of endpoint scope (⚪, one list)

Cloud/SaaS/IdP tactics and techniques (Cloud Accounts, cloud-service
discovery/dashboard techniques, M365/email collection, OAuth abuse, CI/CD
supply chain) — the agent never observes the control planes involved; they
belong to the server's integrations (M9/M10). Physical/peripheral exotica
(firmware ROMs T1542 beyond boot integrity by the updater/watchdog,
hardware implants) — no deployable telemetry surface for a userland agent;
revisit only where the driver tier (W #39) adds vantage.

## The path to "all techniques"

1. **Telemetry-gated rows (📋)** — every one already has a filed issue
   (#136–#138/#39, #264–#267, #351/#355–#357, #362–#366, #371–#374).
2. **Content-gated rows (🟡)** — six coverage-pack issues (M5) turn
   visible-but-unnamed into detected, each a checkbox list per technique:
   #376 initial-access/user-execution · #377 credential-access ·
   #378 discovery/lateral · #379 defense-evasion ·
   #380 collection/exfiltration · #381 privilege-escalation/impact.
3. **Structured fields + generation** — #74 replaces this file with a
   generated matrix so it can never drift from the engines again.
