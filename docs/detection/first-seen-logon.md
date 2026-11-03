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
name alone counts: `HOST\Administrator` is `Administrator`. **`vagrant` is deliberately not
generic**: the lab VMs are signed in to as `vagrant`, and a lab run could otherwise never show the
rule or the join it feeds. The list is the one of `server/lib/fleet-case.ts` (`GENERIC_IDENTITIES`),
copied, not shared: keep them in step.

## What it makes live

The control plane's identity join (#62, #940) reads the event a detection stores. Until this rule,
no rule on `main` fired on a successful logon, so the join joined nothing on a host. This rule is
that source: a detection whose event is a successful `AuthKind::Logon`. It inherits the join's
limits (generic accounts excluded, `vagrant` not, never `LogonFailure`, `ExplicitCredentials` not
counted). Because it alerts once per account, the join sees an identity only the first time the
account logs on to a host after the window. **No lab run is claimed.**

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
odd_hour_exempt_accounts = ["svc_backup|S-1-5-21-1111-2222-3333-1004", "svc_batch", "CORP\\oncall"]
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
  event that carries no SID (Linux and macOS logons) is **not** exempt under such an entry. An entry whose part
  after `|` is not a SID or a `-*` prefix fails the config load.

At most 64 entries, each at most 256 bytes. A logon an exemption suppresses is **counted and logged** once per
account per 8 hours (`odd-hour logon not reported: the account is on the exempt list`), so the list is not an
invisible suppression path. **Both settings are empty by default and only the odd-hour rule reads them**:
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
- **No lab run is claimed**: unit tests only (`crates/rules/src/tests/logon.rs`, five hand mutations
  each failing a named test; `crates/config` tests for the offset). #1088 adds the zone tests: the
  rule with a stand-in zone at fixed instants either side of both 2026 changes, the override in either
  order, a zone with no answer; and the module's own test in the agent, the real `localtime_r` under POSIX
  `TZ` rules either side of the EU and US changes (Unix only). Not run: the agent with a real
  `agent.toml`, a live sshd or 4624 logon at night, **the Windows conversion (compiled for
  `x86_64-pc-windows-gnu`, never run)**, Windows or macOS clippy beyond `enrich`. Per-OS verification
  is #1090 (Linux), #1091 (Windows), #1092 (macOS).
