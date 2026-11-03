# ODD-HOUR-LOGON on a Windows host (#1091), 2026-11-03

Windows 11 Pro 10.0.26300, French UI, time zone `Romance Standard Time` (UTC+1). Agent: release build of
`main` at `81cc6c52` (with #1088), run as `agent --config <toml> run --standalone` in an elevated shell, Event
Log polling sensor on (`Security/4624`, `4648`). Each case used a fresh local account created for the run
(`synthaea_t1091a|b|c`, random password, removed afterwards) and a real logon through
`Start-Process -Credential`. The captures are filtered: only the `auth` events and the T1078 alerts, not the
host's other events (they carry paths and command lines of the machine). `<lab>` stands for the scratch
directory, `<machine>` for the machine part of the local SIDs.

| Case | `[detection]` | Zone | Logons | Result |
| --- | --- | --- | --- | --- |
| `A` | none | `Romance Standard Time`, 16:10 local | 1 | no ODD-HOUR-LOGON (inside 07-20) |
| `B` | `utc_offset_minutes = 600` | `Romance Standard Time`, 16:12 local (= 01:1x at +600) | 2, about 5 s apart | one alert, no repeat |
| `C` | none | `Tokyo Standard Time` set with `tzutil`, 00:16 local | 1 | alert at 00:00 (the platform conversion) |

In `C` a second alert is for the account `Syst`, U+FFFD, `me`: the local SYSTEM account, SID `S-1-5-18`, whose
display name is `Système` on a French Windows. The name reaches the event with the `è` already replaced by
U+FFFD (bytes `ef bf bd` in `C/auth-events.jsonl`), so the generic-account list of `logon.rs`, which holds
English names only, does not match it.

Not covered: the 8 h quiet period on Windows (only the 5 s repeat was observed), service and batch logons by
name (`SERVICE LOCAL`, `SERVICE RÉSEAU`), domain accounts, the logon type of the events, a clock change.
