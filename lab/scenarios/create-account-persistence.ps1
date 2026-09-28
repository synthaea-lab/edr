<#
.SYNOPSIS
    Local account creation persistence detection fidelity scenario for T1136.001.

.DESCRIPTION
    Assertion for "Windows local account creation (event 4720) is detected
    end-to-end via the eventlog sensor": the
    `check_account_creation_persistence` rule fires iff
    `sensor-windows-eventlog` captured the 4720 for the accounts this scenario
    creates.

    Shape: this script creates N local SAM accounts via `net user /add` -- the
    canonical MITRE ATT&CK T1136.001 tradecraft path. Accounts are created
    with a random password, never added to any privileged group (no
    `net localgroup Administrators /add`), and deleted at the end. No
    destructive action, no lateral movement, no outbound network -- benign by
    construction, for detection validation only.

    The scenario intentionally uses `net user /add` rather than the
    PowerShell `New-LocalUser` cmdlet: both paths trigger 4720 the same way
    (Windows writes the event server-side through SAM, regardless of the
    client), but `net user` is the more common shape observed in real-world
    tradecraft (most commodity droppers, Empire, hands-on-keyboard
    post-exploitation).

    Scope: local SAM accounts only (T1136.001). Domain account creation
    (T1136.002) writes 4720 on the DC, not on the reporting machine -- out of
    scope for a userland EDR on member/standalone hosts, and this scenario
    would not be able to test it anyway (needs a domain controller lab).

.NOTES
    Usage:
        1) terminal A (as Administrator):
             target\release\agent.exe run
        2) terminal B (as Administrator -- net user /add requires it):
             powershell -ExecutionPolicy Bypass -File lab\scenarios\create-account-persistence.ps1
        3) expected: exactly one alert per iteration --
             T1136.001 -- account=synthaea-demo-user<N> pid=<id>: local account
             persistence created -- sid: S-1-5-21-...

    No alert means either:
        - The "User Account Management" audit subcategory is not enabled and
          the sensor's own `auditpol` enablement failed silently (check the
          agent's startup log for the "\"User Account Management\" audit
          enabled" line). Less likely than for 4698: UAM is part of the
          Windows default audit policy on both Client and Server SKUs.
        - The eventlog sensor's polling thread is not running (check that
          `sensor-windows-eventlog` is wired into `agent run` and that
          `account_creations_enabled` is `true` in the policy).
        - The rule regressed.

    Prerequisites: run this script AND the agent as Administrator. `net user
    /add` on a system-wide account fails without elevation, and reading the
    Security log likewise requires it.

.LINK
    ATT&CK T1136.001 -- https://attack.mitre.org/techniques/T1136/001/
#>

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

$Iterations = 3
$AccountPrefix = "synthaea-demo-user"
# Random password per iteration -- no shared password between accounts, and each
# is destroyed in the `finally` block so the string never survives the scenario.
# Alphanumeric only (#433): the old 33..126 range could yield `"`, which Windows
# PowerShell 5.1 mangles when passing native arguments, or a leading `/`, which
# net.exe parses as a switch. The fixed suffix guarantees the upper/lower/digit/
# symbol classes of the default complexity policy. 14 characters total: net.exe
# asks for a Y/N confirmation on anything longer, which would hang the script.
function New-BenignPassword {
    $alphabet = [char[]]"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    (-join (1..10 | ForEach-Object { $alphabet | Get-Random })) + "Aa1-"
}

Write-Host "Creating $Iterations local accounts via net user /add..."
$CreatedAccountNames = @()
try {
    for ($i = 1; $i -le $Iterations; $i++) {
        $accountName = "${AccountPrefix}${i}"
        $password = New-BenignPassword
        # /add : create the account.
        # No /activeflag, /passwordchg, /expires -- defaults on all, and the
        # account is not added to any group, so its effective privileges are
        # the "Users" group only. No privilege escalation.
        Invoke-Native net.exe @("user", $accountName, $password, "/add") -Redact $password
        $CreatedAccountNames += $accountName
        Write-Host "  iteration $i done ($accountName)"
        Start-Sleep -Seconds 1
    }

    Write-Host ""
    Write-Host "$Iterations accounts created. The agent should have logged one"
    Write-Host "T1136.001 alert per account within a few seconds of each creation"
    Write-Host "(the eventlog poll interval)."
}
finally {
    Write-Host ""
    Write-Host "Cleanup -- deleting accounts..."
    foreach ($accountName in $CreatedAccountNames) {
        Invoke-NativeCleanup $accountName net.exe @("user", $accountName, "/delete")
    }
}

Write-Host ""
Write-Host "Done. Check the agent terminal: one T1136.001 alert per iteration"
Write-Host "means the eventlog sensor + check_account_creation_persistence rule"
Write-Host "are working end-to-end. No alerts means the pipeline broke somewhere"
Write-Host "between the 4720 emission and the rule evaluation (see .NOTES)."
