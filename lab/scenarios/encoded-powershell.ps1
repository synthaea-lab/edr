<#
.SYNOPSIS
    PowerShell EncodedCommand detection fidelity scenario for T1059.001.

.DESCRIPTION
    Assertion for "PowerShell base64-encoded commands are detected end-to-end
    via the ETW cmdline collector": the `check_encoded_powershell` rule
    (stateless, cmdline substring on `-EncodedCommand` / `-enc` anchored on
    `powershell` or `pwsh`) fires iff the cmdline was captured for this exec
    event.

    Shape: this script spawns N `powershell.exe` invocations with a benign
    payload encoded in the canonical `-EncodedCommand` form. The payload
    decodes to `Write-Host hello` -- no destructive action, no lateral
    movement, no outbound network. Benign by construction, for detection
    validation only.

.NOTES
    Usage:
        1) terminal A (as Administrator):
             target\release\agent.exe run
        2) terminal B:
             powershell -ExecutionPolicy Bypass -File lab\scenarios\encoded-powershell.ps1
        3) expected: exactly one alert per iteration --
             T1059.001 -- pid=<ps> comm=powershell.exe: PowerShell EncodedCommand
             invocation: powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA=

    No alert means either the ETW cmdline collector did not capture the
    cmdline for this exec event (regression on the sensor path) or the rule
    regressed. Also eyeball the raw exec events (`agent run --print-events`
    if the flag is wired): every `powershell.exe` invocation must show its
    `-EncodedCommand` token verbatim.

    Scope: this asserts capture fidelity + rule matching for the canonical
    invocation form. Intermediate parameter truncations (`-Encoded`,
    `-Encod`, ...) are a documented v1 gap of the rule -- follow-up widening
    once telemetry justifies the FP trade-off.

    Also runs on PowerShell Core (`pwsh`) on Linux/macOS -- same anchor, same
    match. Change `powershell.exe` to `pwsh` below and it works there too.

.LINK
    ATT&CK T1059.001 -- https://attack.mitre.org/techniques/T1059/001/
#>

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

$Iterations = 3
# "Write-Host hello" as UTF-16LE base64, the encoding -EncodedCommand expects.
# The first cut used UTF-8 base64, which decodes to garbage and failed every
# run unnoticed: the alert only reads the cmdline, and the exit code was never
# checked (#433).
$Payload = "VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA="

Write-Host "Running $Iterations powershell.exe -EncodedCommand invocations..."
for ($i = 1; $i -le $Iterations; $i++) {
    Invoke-Native powershell.exe @("-EncodedCommand", $Payload)
    Write-Host "  iteration $i done"
    Start-Sleep -Seconds 1
}

Write-Host ""
Write-Host "Done. Check the agent terminal: one T1059.001 alert per iteration"
Write-Host "means the ETW cmdline collector + check_encoded_powershell rule are"
Write-Host "working end-to-end. No alerts means the pipeline broke somewhere"
Write-Host "between exec capture and rule evaluation."
