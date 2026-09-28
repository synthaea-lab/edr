<#
.SYNOPSIS
    Service-install persistence detection fidelity scenario for T1543.003.

.DESCRIPTION
    Assertion for "Windows service installation (event 7045) is detected
    end-to-end via the eventlog sensor": the `check_service_install_persistence`
    rule fires iff `sensor-windows-eventlog` captured the 7045 for the services
    this scenario installs.

    Shape: this script installs N services via `sc.exe create` -- the canonical
    MITRE ATT&CK T1543.003 tradecraft path. The services declare
    `notepad.exe` as their binPath and use `start= demand`, so nothing runs
    automatically; they are deleted at the end. No destructive action, no
    lateral movement, no outbound network -- benign by construction, for
    detection validation only.

    The scenario intentionally uses `sc.exe create` rather than the
    PowerShell `New-Service` cmdlet: both paths trigger 7045 the same way
    (Windows writes the event server-side through the Service Control
    Manager, regardless of the client), but `sc.exe` is the more common
    shape observed in real-world tradecraft (PsExec, most commodity
    droppers, service-based lateral movement).

.NOTES
    Usage:
        1) terminal A (as Administrator):
             target\release\agent.exe run
        2) terminal B (as Administrator -- sc.exe create requires it):
             powershell -ExecutionPolicy Bypass -File lab\scenarios\service-install-persistence.ps1
        3) expected: exactly one alert per iteration --
             T1543.003 -- service=SynthaeaDemoSvc<N> pid=<id>: service
             persistence installed -- image path: C:\Windows\System32\notepad.exe

    No alert means either:
        - The eventlog sensor's polling thread is not running (check that
          `sensor-windows-eventlog` is wired into `agent run`).
        - The rule regressed.
        - Note: unlike 4698, event 7045 lives in the System log (not
          Security) and is emitted unconditionally -- no audit subcategory
          to enable, so a missing alert never points to auditpol.

    Prerequisites: run this script AND the agent as Administrator. The
    Service Control Manager rejects `sc.exe create` without elevation.

    Scope: this asserts capture fidelity + rule matching for the canonical
    `sc.exe create` invocation. The `New-Service` cmdlet path is a
    documented v2 widening -- Windows emits the same 7045 for both, but a
    scenario-side proof of that would need a second script.

.LINK
    ATT&CK T1543.003 -- https://attack.mitre.org/techniques/T1543/003/
#>

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

$Iterations = 3
$ServiceNamePrefix = "SynthaeaDemoSvc"
# notepad.exe: a benign, always-present Windows binary. With `start= demand`
# the service never auto-starts, and it is deleted before anything ever
# invokes it -- only the 7045 registration event matters here.
$BinPath = "C:\Windows\System32\notepad.exe"

Write-Host "Installing $Iterations services via sc.exe create..."
$CreatedServiceNames = @()
try {
    for ($i = 1; $i -le $Iterations; $i++) {
        $serviceName = "${ServiceNamePrefix}${i}"
        # start= demand : manual start, service never runs on its own.
        # DisplayName is cosmetic; the binPath is what the persistence would
        # execute at each service start.
        # Note the `= ` spacing quirk in sc.exe args -- required by the tool.
        Invoke-Native sc.exe @("create", $serviceName, "binPath=", $BinPath, "start=", "demand",
            "DisplayName=", "Synthaea demo service $i (benign, T1543.003 scenario)")
        $CreatedServiceNames += $serviceName
        Write-Host "  iteration $i done ($serviceName)"
        Start-Sleep -Seconds 1
    }

    Write-Host ""
    Write-Host "$Iterations services installed. The agent should have logged one"
    Write-Host "T1543.003 alert per service within a few seconds of each install"
    Write-Host "(the eventlog poll interval)."
}
finally {
    Write-Host ""
    Write-Host "Cleanup -- deleting services..."
    foreach ($serviceName in $CreatedServiceNames) {
        Invoke-NativeCleanup $serviceName sc.exe @("delete", $serviceName)
    }
}

Write-Host ""
Write-Host "Done. Check the agent terminal: one T1543.003 alert per iteration"
Write-Host "means the eventlog sensor + check_service_install_persistence rule"
Write-Host "are working end-to-end. No alerts means the pipeline broke somewhere"
Write-Host "between the 7045 emission and the rule evaluation (see .NOTES)."
