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

Provisional, and stated:

- **07:00 to 20:00 and 8 hours are choices, not measurements.** No weekends, no shifts, no per-host
  profile: a host used around the clock, on-call staff and night shifts alert every night. That is why
  the rule is Low and why it stays off by default.
- **On by default wherever a zone is found** (a change of #1088; it was off until the operator set an
  offset): the rule now alerts on hosts nobody configured. It stays Low, once per account per 8 hours.
- **The zone is the host's setting.** A server left on UTC is judged in UTC; a laptop whose user travels
  is judged by the zone the OS shows at that moment.
- A fixed `utc_offset_minutes` does not follow daylight saving: set it only to override.
- **Windows 4624 includes service and batch logons**, so a named service account that logs on at night
  by schedule alerts. Generic accounts are excluded, a named service account is not.
- The hour is read from the event's own timestamp (event time), so a replayed journal is judged by when
  the logon happened, not when it was read.
- **Linux lab run (#1090, 2026-11-02)**: the agent built from `main` at `8224d72f` (with #1088) on a Fedora 43 VM
  (kernel 7.2.9, `Europe/Paris`, sshd 10.0), real sshd logons by public key from the host, observe-only,
  captures in `lab/captures/test-1090-20261102/` (one directory per case: `alerts.ndjson`, `events.ndjson`,
  `agent.out`, `logons.txt`). Verified:
  - **The Linux logon event** is `auth`, `kind: logon`, `outcome: success`, `target_user` = the account sshd
    names in `Accepted ... for <user>` (`lab1090`, `edr-lab`, `ubuntu`, `ec2-user`), `source_address` = the
    client, `comm: sshd-session`. The account is the login name as typed, not a uid lookup, and carries no
    domain. Every logon produced exactly one such event.
  - **`[detection] utc_offset_minutes` set**: with `0` (14:5x UTC), a logon of `lab1090` raised nothing; with
    `600` (00:xx local), `lab1090` raised ODD-HOUR-LOGON once (`T1078`, Low, "at 00:00 host-local time"); a
    second `lab1090` logon 4 s later did not repeat. The 8 h quiet period was **not** waited out.
  - **Generic accounts**: `ubuntu` and `ec2-user` logged on with the setting at `600` and raised nothing.
    `root` was not tried (no root key on the VM).
  - **Non-generic accounts you did not mean to test alert too**: the lab's own `edr-lab` logons (the SSH
    commands that drive the run) raised the rule in every out-of-window case.
  - **No setting, platform zone** (the case #1088 made default): `Europe/Paris` at 15:5x raised nothing;
    `TZ=Asia/Tokyo` (23:00 local) raised it for `lab1090` and `edr-lab`; log line
    "platform time zone in use, odd-hour logon rule on".
  - **No setting and no zone** (`/etc/localtime` moved away, `TZ` unset, VM clock set to 02:00 UTC so that UTC
    would be outside the window): the agent logged "the host names no time zone; odd-hour logon rule off unless
    utc_offset_minutes is set" and a `lab1090` logon raised nothing. The control at the same clock with
    `Europe/Paris` (03:00 local) raised it. **The rule is therefore silent without a setting only when the host
    names no zone**; on a host with a zone it is on.
  
  Not verified on Linux: the 8 h repeat after the quiet period, a daylight-saving change (the unit and
  `localtime_r` tests cover it), `utc_offset_minutes` overriding a different platform zone on a live agent,
  console, `su` or `sudo` logons, password logins (only public-key ones were made), a logon during a
  failed-then-successful sequence, a root login, and journals on hosts that do not use sshd.
  Run on one VM, on one day; the agent's `date` was moved back 12 h for the no-zone case and the VM was
  reverted afterwards.
- Unit tests (`crates/rules/src/tests/logon.rs`, five hand mutations each failing a named test; `crates/config`
  tests for the offset). #1088 adds the zone tests: the rule with a stand-in zone at fixed instants either
  side of both 2026 changes, the override in either order, a zone with no answer; and the module's own test
  in the agent, the real `localtime_r` under POSIX `TZ` rules either side of the EU and US changes (Unix
  only). Not run: **the Windows conversion (compiled for `x86_64-pc-windows-gnu`, never run)**, a live 4624
  logon, Windows or macOS clippy beyond `enrich`. Windows is #1091, macOS #1092.
