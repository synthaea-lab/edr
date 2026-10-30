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
- **Odd hours are a second rule**, ODD-HOUR-LOGON below, and need the host's UTC offset in `agent.toml`.
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

**It is off unless the operator sets the host's UTC offset.** The event's timestamp is UTC and nothing
else in the agent knows the local time, so the rule has no hour to judge without it:

```toml
[detection]
utc_offset_minutes = 120   # UTC+2; -300 for UTC-5. Between -720 and 840, checked at load.
```

An offset no timezone has fails the config load (fail fast, ADR-0013); `RuleState::set_local_utc_offset_minutes`
refuses it too and the rule stays off.

Provisional, and stated:

- **07:00 to 20:00 and 8 hours are choices, not measurements.** No weekends, no shifts, no per-host
  profile: a host used around the clock, on-call staff and night shifts alert every night. That is why
  the rule is Low and why it stays off by default.
- **A fixed offset.** It does not follow daylight saving: the rule is an hour out for half the year on
  a host that changes, unless the operator changes the setting with the clocks. Reading the host's own
  zone would be a platform query in a sensor crate; not built.
- **Windows 4624 includes service and batch logons**, so a named service account that logs on at night
  by schedule alerts. Generic accounts are excluded, a named service account is not.
- The hour is read from the event's own timestamp (event time), so a replayed journal is judged by when
  the logon happened, not when it was read.
- **No lab run is claimed**: unit tests only (`crates/rules/src/tests/logon.rs`, five hand mutations
  each failing a named test; `crates/config` tests for the offset). Not run: the agent with a real
  `agent.toml`, a live sshd or 4624 logon at night, Windows or macOS clippy.
