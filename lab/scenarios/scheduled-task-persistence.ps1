<#
.SYNOPSIS
    Scheduled-task persistence detection fidelity scenario for T1053.005.

.DESCRIPTION
    Assertion for "Windows scheduled-task creation (event 4698) is detected
    end-to-end via the eventlog sensor": the `check_scheduled_task_persistence`
    rule fires iff `sensor-windows-eventlog` captured the 4698 for the tasks
    this scenario creates.

    Shape: this script creates N one-shot scheduled tasks via `schtasks.exe
    /Create` -- the canonical MITRE ATT&CK T1053.005 tradecraft path. The
    tasks execute `notepad.exe` at a far-future time (so they never actually
    run during the scenario), then are deleted at the end. No destructive
    action, no lateral movement, no outbound network -- benign by
    construction, for detection validation only.

    The scenario intentionally uses `schtasks.exe /Create` rather than the
    PowerShell `New-ScheduledTask` cmdlets: both paths trigger 4698 the same
    way (Windows writes the event server-side, regardless of the client),
    but `schtasks.exe` is the more common shape observed in real-world
    tradecraft (Empire, Cobalt Strike, most commodity droppers).

.NOTES
    Usage:
        1) terminal A (as Administrator):
             target\release\agent.exe run
        2) terminal B (as Administrator -- schtasks.exe /Create requires it):
             powershell -ExecutionPolicy Bypass -File lab\scenarios\scheduled-task-persistence.ps1
        3) expected: exactly one alert per iteration --
             T1053.005 -- task=SynthaeaDemoTask<N> pid=<id>: scheduled task
             persistence created -- action path: C:\Windows\System32\notepad.exe

    No alert means either:
        - The 4698 audit subcategory is not enabled and the sensor's own
          `auditpol` enablement failed silently (check the agent's startup
          log for the "\"Other Object Access Events\" audit enabled" line).
        - The eventlog sensor's polling thread is not running (check that
          `sensor-windows-eventlog` is wired into `agent run`).
        - The rule regressed.

    Prerequisites: run this script AND the agent as Administrator. The
    Security log is not readable without elevation, and `schtasks.exe /Create`
    on a system-wide task fails without it.

    Scope: this asserts capture fidelity + rule matching for the canonical
    `schtasks.exe /Create` invocation. The PowerShell `New-ScheduledTask*`
    cmdlet path is a documented v2 widening -- Windows emits the same 4698
    for both, but a scenario-side proof of that would need a second script.

.LINK
    ATT&CK T1053.005 -- https://attack.mitre.org/techniques/T1053/005/
#>

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

$Iterations = 3
$TaskNamePrefix = "SynthaeaDemoTask"
# notepad.exe: a benign, always-present Windows binary. The tasks are set to
# run at a far-future time and deleted before they trigger, so nothing
# actually executes -- only the 4698 registration event matters here.
$ActionPath = "C:\Windows\System32\notepad.exe"

Write-Host "Creating $Iterations scheduled tasks via schtasks.exe /Create..."
$CreatedTaskNames = @()
try {
    for ($i = 1; $i -le $Iterations; $i++) {
        $taskName = "${TaskNamePrefix}${i}"
        # /SC ONCE /ST 23:59 /SD <far future> : one-shot, never fires in practice.
        # /RL LIMITED : runs under the invoking user, no privilege escalation.
        # /F : overwrite if a stale task from a previous run remains.
        Invoke-Native schtasks.exe @("/Create", "/TN", $taskName, "/TR", $ActionPath,
            "/SC", "ONCE", "/ST", "23:59", "/SD", (Get-FarFutureDate), "/RL", "LIMITED", "/F")
        $CreatedTaskNames += $taskName
        Write-Host "  iteration $i done ($taskName)"
        Start-Sleep -Seconds 1
    }

    Write-Host ""
    Write-Host "$Iterations tasks created. The agent should have logged one"
    Write-Host "T1053.005 alert per task within a few seconds of each creation"
    Write-Host "(the eventlog poll interval)."
}
finally {
    Write-Host ""
    Write-Host "Cleanup -- deleting scheduled tasks..."
    foreach ($taskName in $CreatedTaskNames) {
        Invoke-NativeCleanup $taskName schtasks.exe @("/Delete", "/TN", $taskName, "/F")
    }
}

Write-Host ""
Write-Host "Done. Check the agent terminal: one T1053.005 alert per iteration"
Write-Host "means the eventlog sensor + check_scheduled_task_persistence rule"
Write-Host "are working end-to-end. No alerts means the pipeline broke somewhere"
Write-Host "between the 4698 emission and the rule evaluation (see .NOTES)."
