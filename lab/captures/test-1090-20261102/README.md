# ODD-HOUR-LOGON on a Linux lab VM (#1090), captures of runs 1 and 2 (2026-11-02)

Evidence for the "Linux lab runs" bullet of `docs/detection/first-seen-logon.md`. Run 3 (2026-11-03, the 8 h quiet period) is in `../test-1090c-20261103/`.

Fedora 43 VM (kernel 7.2.9, `Europe/Paris`, sshd 10.0), real sshd logons by public key from the host, agent in observe-only. One directory per case:

| Case | Setting / zone | Logons | What the run shows |
| --- | --- | --- | --- |
| `A-offset0-inwindow` | `utc_offset_minutes = 0` (14:5x) | `lab1090` | no ODD-HOUR-LOGON |
| `B-offset600-outside` | `utc_offset_minutes = 600` (00:xx host-local) | `lab1090` twice, `ubuntu`, `ec2-user` | `lab1090` alerts once, the second logon does not repeat; `ubuntu` and `ec2-user` (generic accounts) are silent; the driver's own `edr-lab` logon alerts |
| `C-nosetting-paris` | no setting, `Europe/Paris` (15:5x) | `lab1090` | none (inside the window) |
| `D-nosetting-tokyo` | no setting, `TZ=Asia/Tokyo` (23:00) | `lab1090` twice | `lab1090` and `edr-lab` alert, log line "platform time zone in use" |
| `E1-nozone-utc0200` | no setting, `/etc/localtime` moved, `TZ` unset, clock 02:00 UTC | `lab1090` twice | none; the log says the host names no time zone and the rule is off |
| `E2-paris-utc0200` | no setting, Paris, clock 02:00 UTC (03:00 local) | `lab1090` | `lab1090` and `edr-lab` alert |
| `F-expiry-8h` | `utc_offset_minutes = 600`, account `edr-lab` | `edr-lab` four times, clock moved +9 h before the third | first attempt at the 8 h repeat. It does not test the quiet period: +9 h lands inside the work window, where the hour check returns first. Superseded by run 3 |

## What each case directory holds
- `alerts.ndjson`: every alert of the run, not only ODD-HOUR-LOGON (T1078). Other detections of the host appear in it (service first seen, and so on).
- `logons.txt`: the driver's log of the logons it made, with times. In `F-expiry-8h` its first line is a `date` usage error of the driver (`date: opérande supplémentaire « %T »`); its effect on the run is not recorded.
- `cfg-<case>.toml`: the agent configuration of the case (cases A to E; `F` has none). The certificate paths in it are the VM's own and carry no secret.
- `events-auth.ndjson`: only the `auth` events of the run's event stream (one per logon), extracted from `events.ndjson`.

`run-case.sh` and `run-expiry.sh` are the drivers. The lab VM's sudo password is masked as `<lab-password>` in them; nothing else was changed.

## What is NOT here
- The raw `events.ndjson` and `agent.out` of each case (about 14 MB: the whole host's event stream and agent log). They stay in the author's lab notes. The `auth` events that matter are in `events-auth.ndjson`; whatever else is in the raw stream can not be checked from this repository.
- The notes of the runs (`issue-1090.md`).
- Not recorded: the exact commit of the agent of run 2 (branch `feat/1103-signal-generate` only), and whether `chronyd` was stopped in runs 1 and 2.
- Not verified by any of these runs: a DST change live, password, console, `su` and `sudo` logons, `root`. One VM, one day, one OS.
