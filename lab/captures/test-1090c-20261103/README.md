# ODD-HOUR-LOGON, the 8 h quiet period on a live Linux agent (#1090, run 3, 2026-11-03)

Fedora 43 VM (`Europe/Paris`), agent built from `main` at `81cc6c52` (the binary is `~/edr-main/agent`; `x1090.sh` runs it from the #1103 checkout `~/edr-1103` with `--content-dir .` and a base config copied from `~/lab1103/base.toml`, which does not matter for ODD-HOUR-LOGON, compiled into `crates/rules`), no setting (platform zone in use: log line "platform time zone in use, odd-hour logon rule on"), default window 07:00-20:00, one fresh account `ob_q`, real sshd logons. `chronyd` was stopped and the VM clock set by hand between steps.

- `run/scenario.log`: the steps and what was expected at each (the log records the plan, the alerts record what happened): first odd-hour logon (alert expected), a second 4 s later (silent), 7 h 30 later (silent), 8 h 30 later (alert), 30 min after that alert (silent), 21 h later (alert).
- `run/alerts.ndjson`: the alerts of the run, among them ODD-HOUR-LOGON for `ob_q` at 21:00, 05:00 and 03:00 and for the driver's own `edr-lab` ssh logons at 04:00 and 03:00. The result table is in the "Linux lab runs" bullet of `docs/detection/first-seen-logon.md`.
- `x1090.sh`: the driver. The lab VM's sudo password is masked as `<lab-password>`.

Not here: the agent log (`agent.out`) and the notes of the run (`issue-1090.md`), kept in the author's lab notes.
