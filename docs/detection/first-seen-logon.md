# First-seen and odd-hour logon (FIRST-SEEN-LOGON, ODD-HOUR-LOGON, #376)

Two rules over the `Auth` events, the second at the end of this page. The first: `RuleState::check_first_seen_logon` (`crates/rules/src/state.rs`),
with the generic-account list and the baseline in `crates/rules/src/logon.rs`. It is the endpoint
half of the T1078 (valid accounts) line of the Initial Access pack (#376). Fleet-wide anomalies
(an account new to the fleet, not to one host) stay in M9.

## The shape

A **successful** logon (`AuthOutcome::Success`, `AuthKind::Logon`) of an account that did not log on
to this host during the **learning window**: the 24 hours after the first successful logon of any
account the rule state saw. One alert per account, Low, `T1078`; the account is in the baseline
afterwards. The message carries the account and the source address when the event has one.

| Event | Counts |
| --- | --- |
| `Logon` + `Success` (Windows 4624, Linux sshd accepted, macOS login) | yes |
| `LogonFailure` | **never**: its user name is chosen by whoever tries it, and a failed name does not enter the baseline |
| `ExplicitCredentials`, `PrivilegedSession` (`su`, `sudo`) | no: they name an account an attacker already on the host picks |

The account is compared in lowercase, the full name (`CORP\bob` and `bob` are two accounts). The
learning clock starts at the first logon of **any** account, a generic one included: a host that only
`root` logs on to for days must not leave an intruder's first account in a window that never began.

## Generic accounts

Not alerted, not learned: `root`, `system`, `administrator`, `nobody`, `daemon`, the Windows service
identities (`NT AUTHORITY\SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `ANONYMOUS LOGON`), machine
accounts (`HOST$`), `DWM-n` and `UMFD-n`, and the default logins of cloud and distribution images
(`ubuntu`, `ec2-user`, `debian`, `fedora`, `centos`, `rocky`, `cloud-user`, `azureuser`, `admin`). The
name alone counts: `HOST\Administrator` is `Administrator`. On Windows the account is also generic
by its SID when the event carries one (`S-1-5-7`, `S-1-5-18`, `S-1-5-19`, `S-1-5-20`): the name of
those is localized (the SYSTEM account of a French Windows is named in French, and the event can
carry the name with a letter already lost), so a name list alone cannot recognise them (#1091).
**`vagrant` is deliberately not generic**: the lab VMs are signed in to as `vagrant`, and a lab run
could otherwise never show the rule or the join it feeds. The name list is the one of
`server/lib/fleet-case.ts` (`GENERIC_IDENTITIES`), copied, not shared: keep them in step. The SID
rule is in the agent only: the control plane's join reads the name, so it still sees a localized
SYSTEM name as an identity (a follow-up, not done here).

## What it makes live

The control plane's identity join (#62, #940) reads the event a detection stores. Until this rule,
no rule on `main` fired on a successful logon, so the join joined nothing on a host. This rule is
that source: a detection whose event is a successful `AuthKind::Logon`. It inherits the join's
limits (generic accounts excluded, `vagrant` not, never `LogonFailure`, `ExplicitCredentials` not
counted). Because it alerts once per account, the join sees an identity only the first time the
account logs on to a host after the window. The lab runs are recorded under "Lab runs" below; the server join was not exercised by the Linux run (observe-only).

## Lab runs

- **Windows (#1091, 2026-11-03)**: Windows 11 (French UI, `Romance Standard Time`), a release agent built
  from `main` at `81cc6c52`, run elevated with `--standalone`, a real local account per case logging on
  through `Start-Process -Credential`, captures in `lab/captures/test-1091-20261103/` (filtered to the `auth`
  events and the T1078 alerts; its README gives the table). Verified:
  - **The Windows logon event** is `auth`, `kind: logon`, `outcome: success`, `target_user` the bare account
    name (no domain, no machine), `target_user_sid`, `source_address` `::1`; each logon also produced an
    `explicit_credentials` event (4648), which the rule does not count.
  - **Inside the window, nothing**: a logon at 16:11 local with no `[detection]` section raised nothing.
  - **`utc_offset_minutes = 600`**: the first logon of a new account at 01:1x (as the rule saw it) raised
    ODD-HOUR-LOGON once (T1078, Low); a second logon of the same account about 5 s later did not repeat.
  - **The Windows time-zone conversion** (`GetDynamicTimeZoneInformation`, the part this page said was never
    run): with no `[detection]` section and the system zone set to `Tokyo Standard Time` with `tzutil`, a
    logon at 00:15 local raised the alert at 00:00. The message prints the hour only (`{hour:02}:00`).
  - **A defect found**: the same run alerted on the account `Système`, the local SYSTEM account (SID
    `S-1-5-18`) of a French Windows. The generic-account list holds English names only, and the name reaches
    the event with its `è` already replaced by U+FFFD, so no spelling of it can match. The SID is on the
    event, and since #1125 the rule treats `S-1-5-7`, `-18`, `-19` and `-20` as generic whatever the
    name. The name loss itself is #1126.
  - **Not covered**: the 8 h quiet period on Windows (only the 5 s repeat), service and batch logons by name
    (`SERVICE LOCAL`, `SERVICE RÉSEAU`, not run), domain accounts, the logon type, and Windows or macOS
    clippy beyond `enrich`.

- **Linux lab runs (#1090, 2026-11-02 and 2026-11-03)**, three runs on one Fedora 43 VM (kernel 7.2.9,
  `Europe/Paris`, sshd 10.0), real sshd logons by public key from the host, observe-only:
  - **Run 1, 2026-11-02**: agent built from `main` at `8224d72f` (with #1088). Every case below except the
    8 h repeat.
  - **Run 2, 2026-11-02** (`F-expiry-8h`, account `edr-lab`, `utc_offset_minutes = 600`): agent built from the
    `feat/1103-signal-generate` branch (#1103) in the VM's `~/edr-1103`; its commit was not recorded, so only
    the branch is known. A first attempt at the 8 h repeat (see below); run 3 supersedes it.
  - **Run 3, 2026-11-03**: agent built from `main` at `81cc6c52`. The 8 h repeat (see below).

  **Where the evidence is**: `lab/captures/test-1090-20261102/` (runs 1 and 2, one directory per case:
  `alerts.ndjson`, `logons.txt`, the agent configuration, `events-auth.ndjson` and the drivers) and
  `lab/captures/test-1090c-20261103/` (run 3: the alerts, the step log and the driver); each has a README.
  What is **not** in the repository: the raw `events.ndjson` and `agent.out` of each case (about 14 MB, the
  whole host's event stream) and the notes of the runs (`issue-1090.md`) stay in the author's lab notes, and
  the lab password is masked in the drivers. Whether `chronyd` was stopped in runs 1 and 2 is not recorded;
  in run 3 it was.

  Verified:
  - **The Linux logon event** is `auth`, `kind: logon`, `outcome: success`, `target_user` = the account sshd
    names in `Accepted ... for <user>` (`lab1090`, `edr-lab`, `ubuntu`, `ec2-user`), `source_address` = the
    client, `comm: sshd-session`. The parser takes the name from the log text (between " for " and " from",
    `crates/sensors/linux/journal/src/classify.rs`), never by a uid lookup, adds no domain and keeps whatever
    sshd logged: a `bob@corp` and a `bob` are two accounts. `comm` is `SYSLOG_IDENTIFIER` (`auth.rs`): it is
    `sshd-session` on OpenSSH 9.8 and later, `sshd` on older versions. **`target_user_sid` is absent on Linux**
    (`auth.rs:162`, "Linux: no SID concept"), so an exemption bound to a SID (#1108) or a SID-based generic
    list (#1125) cannot match a Linux logon: only the name list applies. Every logon produced exactly one
    such event.
  - **`[detection] utc_offset_minutes` set, and overriding the platform zone** (run 1): with `0` (14:5x UTC),
    a logon of `lab1090` raised nothing; with `600` (00:xx local), `lab1090` raised ODD-HOUR-LOGON once
    (`T1078`, Low, "at 00:00 host-local time"); a second `lab1090` logon 4 s later did not repeat. The VM was
    on `Europe/Paris`, where the same instant is 15:5x and inside the window, so the setting did override a
    different live platform zone.
  - **The failed first attempt at the 8 h repeat** (run 2): the first `edr-lab` logon alerted, the second 4 s
    later did not, then the VM's wall clock was moved +9 h and two more logons raised nothing. **That null
    result says nothing about the cooldown.** The logon event's time is journald's wall clock
    (`__REALTIME_TIMESTAMP`, `record.realtime_us` in `crates/sensors/linux/journal/src/record.rs`, copied to
    `timestamp_ns` in `auth.rs`), so moving the clock does move it. But the run started at 15:23 UTC, which is 01:2x local with `utc_offset_minutes = 600`
    (the alert says "at 01:00 host-local time"); plus 9 h it is 10:2x local, inside
    `WORK_HOURS_LOCAL` (7, 20), and `OddHours::observe` (`crates/rules/src/logon.rs:196-200`) returns `None`
    on the hour check before it looks at the quiet period. The experiment could not tell "cooldown still
    active" from "cooldown elapsed". (`saturating_sub` also means a clock moved backwards reads as still
    inside the quiet period.)
  - **8 h quiet period, by moving the clock** (run 3): Fedora 43 (`Europe/Paris`), no setting (platform
    zone in use), default window 07-20, one fresh account, real sshd logons, `chronyd` stopped and the
    journald wall clock moved by hand. First alert at 21:00 host-local time; a logon 4 s later silent; **7 h
    30 later silent**; **8 h 30 later alert**; 30 min after that alert silent; **21 h later alert**. So the
    quiet period holds on a live agent, stays silent inside it, alerts after it, and restarts at each alert.
    The driver and alerts are in `lab/captures/test-1090c-20261103/`.
  - **Generic accounts**: `ubuntu` and `ec2-user` logged on with the setting at `600` and raised nothing.
    `root` was not tried (no root key on the VM).
  - **Accounts used to drive the run alert too**: the lab's own `edr-lab` logons (the SSH commands that
    drive the run) raised the rule in every out-of-window case, since it is not a generic account.
  - **No setting, platform zone** (the case #1088 made default): `Europe/Paris` at 15:5x raised nothing;
    `TZ=Asia/Tokyo` (23:00 local) raised it for `lab1090` and `edr-lab`; log line
    "platform time zone in use, odd-hour logon rule on".
  - **No setting and no zone** (`/etc/localtime` moved away, `TZ` unset, VM clock moved back 12 h to 02:00
    UTC so that UTC would be outside the window; the VM was reverted afterwards): the agent logged "the host
    names no time zone; odd-hour logon rule off unless utc_offset_minutes is set" and a `lab1090` logon
    raised nothing. The control at the same clock with `Europe/Paris` (03:00 local) raised it. **The rule is
    therefore silent without a setting only when the host names no zone, or its zone cannot convert the
    present** (the agent then logs "the platform gave no time zone offset", `agent/src/commands/common.rs:110`;
    that second case was not reproduced); on a host with a zone it is on.

  Not verified on Linux: a daylight-saving change (the unit and `localtime_r` tests cover it), the setting
  changed while the agent runs and the order of zone and setting at startup (the unit tests cover the
  order), console, `su` or `sudo` logons, password logins (only public-key ones were made), a logon during a
  failed-then-successful sequence, a root login, and journals on hosts that do not use sshd.

## Provisional and stated gaps

- **24 hours is provisional**: one working day, with no measurement behind it.
- **The baseline is in memory.** An agent restart, an update included, begins a new learning window,
  and an account that logs on during a window is learned without an alert, an intruder's included.
  No state is read from the host (`last`, the Security log) to seed it.
- **Odd hours are a second rule**, ODD-HOUR-LOGON below, and need the host's local time: the platform's time zone, or the operator's UTC offset in `agent.toml`.
- **Expected false positives**: a domain controller or file server (every user's first logon), a new
  hire, a service account first used after an install, a reinstalled host. Hence Low. The baseline
  holds 16 384 accounts; past that an evicted account is first-seen again.
- Windows 4624 includes service, batch and network logons, so a new service account alerts on its
  first use.

## ODD-HOUR-LOGON

`RuleState::check_odd_hour_logon` (`crates/rules/src/state.rs`, clock in `crates/rules/src/logon.rs`).
The same event gate as above (a **successful** `AuthKind::Logon`, never a failure, `su` or `sudo`) and
the same generic-account list, but no learning window: a logon of a non-generic account whose
**host-local hour is outside 07:00 to 20:00** alerts, `T1078`, **Low**, with the account, the source
address when there is one and the local hour. One alert per account per 8 hours, so a night's
reconnects are one finding. It is independent of FIRST-SEEN-LOGON: a new account at night raises both.

**The host's local time comes from the platform's time zone, and the rule is on only if a zone is found
(#1088).** The event's timestamp is UTC, so the rule converts it with the zone's rules **at that
instant**: a logon either side of a daylight-saving change lands on the hour the host's clock showed.
The agent asks the platform at startup (`agent/src/commands/localzone.rs`):

| Platform | Source | Found when |
| --- | --- | --- |
| Linux, macOS | `tzset` + `localtime_r` (`TZ`, `/etc/localtime`, the zoneinfo file); `tzset` is called on every conversion, so a zone changed while the agent runs is followed | `TZ` is set or `/etc/localtime` exists |
| Windows | `GetDynamicTimeZoneInformation` + `SystemTimeToTzSpecificLocalTimeEx` (year-aware rules) | always (a zone setting always exists) |

**No zone database is bundled**: the platform has one and keeps it current; the cost is three small
platform calls and an answer only as right as the host's own zone setting. A Unix host with no `TZ` and
no `/etc/localtime` (a minimal container) is silently UTC to the C library, which no one chose, so it
counts as **no zone** and the rule stays off. A source that cannot convert the present is refused the
same way, and an instant the source cannot convert is not judged (no fallback to UTC).

The operator's fixed offset **overrides** the zone, for a host whose zone is wrong or absent:

```toml
[detection]
utc_offset_minutes = 120   # UTC+2; -300 for UTC-5. Between -720 and 840, checked at load.
```

An offset no timezone has fails the config load (fail fast, ADR-0013); `RuleState::set_local_utc_offset_minutes`
refuses it too. A fixed offset does not follow daylight saving.

## Calibration: the window, shifts, service accounts (#1089)

**The window is `[detection] work_hours`, 07:00 to 20:00 by default.** The default is a plain working day,
a choice with one weak measurement behind it (below), and is named `WORK_HOURS_LOCAL` in
`crates/rules/src/exclusions.rs`. An operator whose people do not work those hours declares theirs:

```toml
[detection]
work_hours = [22, 6]                          # a night shift: 22:00 to 06:00 is ordinary, the day is not
odd_hour_exempt_accounts = ["svc_backup|S-1-5-21-1111-2222-3333-1004", "svc_batch"]
```

`work_hours = [start, end]`: `start` 0 to 23, `end` 1 to 24, different; `start` greater than `end` wraps
midnight; `[0, 24]` makes every hour ordinary, so the rule never alerts (the agent says so in its log).
`odd_hour_exempt_accounts` lists the accounts whose odd-hour logons are expected (on-call staff, the service or
batch account of a schedule). Each entry is `NAME` or `NAME|SID`:

- **`NAME`** is matched without case against the account **as the logon reports it**, and the Windows logon event
  (4624) reports the bare account name with no domain. **A bare entry therefore exempts any account of that name
  on the host, including a local one an intruder with local admin creates under it** (reproduced live on a
  Windows 11 host, 2026-11-03: the listed local account raised nothing, an unlisted one raised the alert). A
  `DOMAIN\name` entry matches only an event that reports exactly that string, which no sensor does for a logon
  today; a UPN (`name@corp.com`) or `corp/name` is another string and a bare entry does not match it (the logon
  alerts, which is the safe side).
- **`NAME|SID`** binds the entry to the account's SID, which the Windows event carries and an intruder cannot
  choose: `svc_backup|S-1-5-21-1111-2222-3333-1004` exempts that account only, and
  `svc_backup|S-1-5-21-1111-2222-3333-*` any account of that name below that domain (or machine) SID prefix. An
  prefix entry exempts any account of that name that the prefix's authority can create: a machine prefix still
  lets a local admin create a look-alike (a new local account gets `<machine SID>-<new RID>`), and a domain prefix
  lets anyone who can create domain accounts do the same. Prefer the exact SID. An
  event that carries no SID (Linux and macOS logons) is **not** exempt under such an entry. An entry whose part
  after `|` is not a SID or a `-*` prefix fails the config load.

At most 64 entries, each at most 256 bytes. A logon an exemption suppresses is **counted and logged** once per
(name, SID) per 8 hours (`odd-hour logon not reported: the account is on the exempt list`, with the running count at
info and the account and the SID at debug, since they come from the event): a look-alike account under an exempt name
leaves its own line even within the quiet period of the real one. The count has no health beacon field (that needs a
schema and a server change for one counter), so the log line is how it is read. An entry that contains a backslash is
warned about at start: it exempts nothing today. **Both settings are empty by default and only the odd-hour rule reads them**:
FIRST-SEEN-LOGON still sees an exempt account, and nothing is exempt until the operator names it. A malformed
window or list fails the config load (ADR-0013), and the error names the first bad entry. The rules apply the
same bounds themselves: a window that is not one is refused and the previous one kept; a list over 64 entries is
cut to 64, and a blank, over-long or malformed entry is dropped, not read as something broader.

**Measurement (one host, stated with its limits).** `last -F` on a Linux workstation (Fedora 43, Europe/Paris),
2026-10-10 to 2026-11-02: 148 login records of **one account**, 124 on pseudo-terminals and 24 on consoles.
Local hour: 72 at 09:00, 76 more between 10:00 and 17:00, **12 outside 07:00 to 20:00** (3 at 20:00, 9 at
21:00), none between 22:00 and 08:00. Weekend days: 20 of 148. Limits: one host, one account, one person's
working pattern; `wtmp` counts every terminal opened, which the agent does not see as a logon (it sees sshd and PAM
sessions through the journal); no service or batch account, no Windows host, no macOS host, no logon types. **It
supports "a workday window removes most of the noise on a workstation" and nothing about servers, shifts,
Windows or a fleet**; the Windows and macOS measurements are still to do (#1091, #1092).

**What was changed and what was not, with the reason:**

| Case | Decision |
| --- | --- |
| Night shifts, on-call staff | **Changed**: the operator declares the window (`work_hours`, overnight wrap) and the on-call accounts. Default window unchanged. |
| Service or batch logon of a named account | **Changed, by naming**: `odd_hour_exempt_accounts`. Telling them apart by logon type is **not possible** today: `AuthEvent` carries no logon type (the Windows 4624 `LogonType` is read by the sensor and dropped), so it needs a schema field and a version bump; recorded, not done. A heuristic on the name (`svc_`, `svc-`) or on `source_address` being absent was refused: the first blinds the rule for anyone who picks such a name, the second is true of console logons as well. |
| Weekends | **No change, no safe one.** Counting a weekend day as odd adds an alert for every weekend logon (13 % of the measured records); counting it as ordinary blinds the rule on it. Neither is better than the other without a fleet baseline. Stays an operator concern; M9 fleet anomalies. |
| A per-account learned pattern | **Not built**: it needs a persisted baseline per account and hour (the FIRST-SEEN baseline is in memory and resets on restart) and a learning window longer than a day to mean anything; an intruder logging on during it is learned silently. M9. |

Provisional, and stated:

- **07:00 to 20:00 and 8 hours are choices, not measurements** (one weak measurement, above). No
  weekends and no per-host profile: a host used around the clock alerts every night unless its operator
  declares `work_hours`; on-call staff and service accounts alert unless named. That is why the rule is Low.
- **On by default wherever a zone is found** (a change of #1088; it was off until the operator set an
  offset): the rule now alerts on hosts nobody configured. It stays Low, once per account per 8 hours.
- **The zone is the host's setting.** A server left on UTC is judged in UTC; a laptop whose user travels
  is judged by the zone the OS shows at that moment.
- A fixed `utc_offset_minutes` does not follow daylight saving: set it only to override.
- **Windows 4624 includes service and batch logons**, so a named service account that logs on at night
  by schedule alerts until the operator lists it in `odd_hour_exempt_accounts`. Generic accounts are excluded.
- The hour is read from the event's own timestamp (event time), so a replayed journal is judged by when
  the logon happened, not when it was read.
- Unit tests (`crates/rules/src/tests/logon.rs`, five hand mutations each failing a named test; `crates/config`
  tests for the offset). #1088 adds the zone tests: the rule with a stand-in zone at fixed instants either
  side of both 2026 changes, the override in either order, a zone with no answer; and the module's own test
  in the agent, the real `localtime_r` under POSIX `TZ` rules either side of the EU and US changes (Unix
  only). The lab runs are under "Lab runs" above. Not run: the agent with a real `agent.toml` on Windows or
  macOS beyond what "Lab runs" lists, Windows or macOS clippy beyond `enrich`. Per-OS verification is #1090
  (Linux, in "Lab runs"), #1091 (Windows, done there), #1092 (macOS).
