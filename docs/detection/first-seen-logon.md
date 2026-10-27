# First-seen logon (FIRST-SEEN-LOGON, #376)

One rule over the `Auth` events: `RuleState::check_first_seen_logon` (`crates/rules/src/state.rs`),
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
- **Odd hours are not built, on purpose.** The event carries a UTC timestamp and no timezone, and no
  part of the agent knows the host's local time. Saying "outside working hours" in UTC would be wrong
  on most hosts. It needs a local-time source (an agent setting or a platform query, which belongs in
  a sensor crate) before it can be written honestly; the hour window would then be provisional too.
- **Expected false positives**: a domain controller or file server (every user's first logon), a new
  hire, a service account first used after an install, a reinstalled host. Hence Low. The baseline
  holds 16 384 accounts; past that an evicted account is first-seen again.
- Windows 4624 includes service, batch and network logons, so a new service account alerts on its
  first use.
