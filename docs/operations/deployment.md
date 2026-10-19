# Deployment

Installing and enrolling agents per platform, control-plane deployment, and upgrade
strategy (canary rings).

## Windows: event log prerequisites

The Windows event log sensor (`crates/sensors/windows/eventlog`) reads two kinds of
sources:
- Security audit subcategories. The agent turns these on itself at start-up.
- Operational log channels. The agent **never** turns these on (#786). A disabled
  channel is the host's policy, and changing it belongs to your deployment, as with
  AppLocker.

### What the agent enables itself

At start-up, the agent enables these Security audit subcategories with `auditpol /set
/subcategory:<GUID> /success:enable /failure:enable`. It uses the GUID so that it works
whatever the OS language. A failure is logged as a warning naming the coverage that is
lost, together with the command to run by hand.

| Subcategory | Events | Used for |
| --- | --- | --- |
| Logon, Special Logon | 4624, 4625, 4648, 4672 | logons, failures, explicit credentials, privileged logons |
| User Account Management | 4720 | account creation |
| Other Object Access Events | 4698, 4702 | scheduled task created or updated. This one is **not** in Windows' default audit policy. |

If a Group Policy manages the advanced audit policy, it can reset these subcategories
at its next refresh. Include them in that policy.

### What you must enable

The sensor reads these Operational channels:

- `System` (7045, service installed)
- `Microsoft-Windows-AppLocker/EXE and DLL`, `/MSI and Script`, `/Packaged app-Execution`, `/Packaged app-Deployment`
- `Microsoft-Windows-CodeIntegrity/Operational` (WDAC)
- `Microsoft-Windows-Windows Defender/Operational`
- `Microsoft-Windows-TaskScheduler/Operational` (106, task registered)
- `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`

On a Windows 11 25H2 client, measured in #786, all of them are on by default
**except `Microsoft-Windows-TaskScheduler/Operational`**. That channel is Task
Scheduler's "All Tasks History" switch, off by default on client SKUs. While it stays
off, the 106 path sees nothing. Scheduled-task persistence then relies on Security
4698/4702 alone, which the agent enables as shown above.

To enable a channel, from an elevated prompt:

```
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true
```

Check it with `wevtutil gl "<channel>"`, which should show `enabled: true`. To set it
fleet-wide, run the same command through your configuration management, for example a
startup script.

### How to tell on a given host

At start-up the agent checks each channel it reads. A disabled one gets **one warning**
in the agent log, naming:
- the channel;
- the detection targets that will see nothing;
- the `wevtutil` command above.

The count of disabled channels is kept in `EventLogCounters::disabled_channels`. The
check runs at start-up only. A channel switched off while the agent runs is not
reported yet (#798).
