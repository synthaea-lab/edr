<#
.SYNOPSIS
    Passive observer for the RDP success-after-failures rule (#285, #700):
    which events does ONE failed and ONE successful Remote Desktop logon leave
    behind, and in which order? Lab VM, elevated.

.DESCRIPTION
    The rule treats RemoteConnectionManager event 1149 ("user authentication
    succeeded") as the success and Security 4625 as the failures. That only
    holds if 1149 is NOT written for a connection whose credentials were
    refused. The Microsoft documentation and field reports disagree when
    Network Level Authentication (NLA) is off, so this has to be observed.

    This script connects to nothing and tries no credential. It reads the host's
    settings, waits while YOU make the connections by hand from another machine
    (or `mstsc` from the host), then lists what the logs recorded in that window:

      - Security 4625 (failed logon) and 4624 (logon), logon types 3 and 10
      - TerminalServices-RemoteConnectionManager/Operational (1149 and the rest)
      - TerminalServices-LocalSessionManager/Operational (21 to 25)

    Suggested run, once per NLA setting (the script prints the current one):
      1. start the script;
      2. make ONE connection with a WRONG password, and stop at the refusal;
      3. make ONE connection with the right password, then sign out;
      4. press Enter in the script.
    Then switch NLA (System Properties > Remote > "Allow connections only from
    computers running Remote Desktop with NLA") and repeat. The question to
    answer for each setting is whether a 1149 appears for step 2.

    -SinceMinutes analyses the last N minutes instead of waiting (no prompt),
    which is also how to re-read a run afterwards.

    ASCII only, Windows PowerShell 5.1 (#433).

.PARAMETER OutDir
    Where timeline.csv and summary.txt go. Default: .\rdp-observe-<timestamp>.
.PARAMETER SinceMinutes
    Analyse the last N minutes and exit, without prompting.
#>
[CmdletBinding()]
param(
    [string]$OutDir = "",
    [int]$SinceMinutes = 0
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated PowerShell (the Security log needs it)."
}

if (-not $OutDir) {
    $OutDir = Join-Path (Get-Location) ("rdp-observe-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$summary = Join-Path $OutDir "summary.txt"

function Say {
    param([string]$Text = "")
    Write-Host $Text
    Add-Content -Path $summary -Value $Text
}

function Get-DataField {
    # EventData/Data[@Name] of an event, or "" when absent.
    param([xml]$Xml, [string]$Name)
    $node = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($node) { return [string]$node.'#text' }
    return ""
}

function Get-RdpSettings {
    $ts = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $tcp = Join-Path $ts "WinStations\RDP-Tcp"
    $deny = (Get-ItemProperty -Path $ts -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
    $nla = (Get-ItemProperty -Path $tcp -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    $layer = (Get-ItemProperty -Path $tcp -Name SecurityLayer -ErrorAction SilentlyContinue).SecurityLayer
    $port = (Get-ItemProperty -Path $tcp -Name PortNumber -ErrorAction SilentlyContinue).PortNumber
    return @{ Deny = $deny; Nla = $nla; Layer = $layer; Port = $port }
}

Say "# RDP event observation (#285 / #700)"
Say ("Date (UTC): " + (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))
Say ("Host: " + $env:COMPUTERNAME)
$os = Get-CimInstance Win32_OperatingSystem
Say ("OS: " + $os.Caption + " build " + $os.BuildNumber)
$s = Get-RdpSettings
$nlaText = if ($s.Nla -eq 1) { "ON (NLA required)" } elseif ($s.Nla -eq 0) { "OFF (NLA not required)" } else { "unknown" }
Say ("Remote Desktop connections allowed: " + $(if ($s.Deny -eq 0) { "yes" } elseif ($s.Deny -eq 1) { "NO (fDenyTSConnections=1)" } else { "unknown" }))
Say ("NLA (UserAuthentication): " + $nlaText + "   SecurityLayer: " + $s.Layer + "   port: " + $s.Port)
Say ""

if ($SinceMinutes -gt 0) {
    $start = (Get-Date).AddMinutes(-$SinceMinutes)
    Say ("Analysing the last " + $SinceMinutes + " minutes.")
}
else {
    $start = Get-Date
    Say "Make the connections now, from ANOTHER machine or with mstsc:"
    Say "  1. ONE connection with a WRONG password (stop at the refusal)"
    Say "  2. ONE connection with the right password, then sign out"
    Read-Host "Press Enter here when both are done" | Out-Null
}
$end = Get-Date
Say ""

$rows = New-Object System.Collections.ArrayList

function Add-Events {
    param([string]$Label, [hashtable]$Filter, [scriptblock]$Describe)
    try {
        $events = @(Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like "*NoMatchingEventsFound*") { return }
        Say ("  [" + $Label + "] not readable: " + $_.Exception.Message)
        return
    }
    foreach ($e in $events) {
        [xml]$xml = $e.ToXml()
        [void]$rows.Add([pscustomobject]@{
            Time    = $e.TimeCreated.ToUniversalTime().ToString("HH:mm:ss.fff")
            Source  = $Label
            Id      = $e.Id
            Detail  = (& $Describe $xml $e)
        })
    }
}

$common = @{ StartTime = $start; EndTime = $end }

Add-Events "Security" ($common + @{ LogName = "Security"; Id = 4625 }) {
    param($xml, $e)
    $type = Get-DataField $xml "LogonType"
    if ($type -in @("3", "10")) {
        "FAILED logon type=" + $type + " user=" + (Get-DataField $xml "TargetUserName") +
        " ip=" + (Get-DataField $xml "IpAddress") + " status=" + (Get-DataField $xml "Status") +
        " sub=" + (Get-DataField $xml "SubStatus")
    }
    else { $null }
}
Add-Events "Security" ($common + @{ LogName = "Security"; Id = 4624 }) {
    param($xml, $e)
    $type = Get-DataField $xml "LogonType"
    if ($type -in @("3", "10")) {
        "logon type=" + $type + " user=" + (Get-DataField $xml "TargetUserName") +
        " ip=" + (Get-DataField $xml "IpAddress")
    }
    else { $null }
}
$rcm = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
Add-Events "RCM" ($common + @{ LogName = $rcm }) {
    param($xml, $e)
    $u = $xml.Event.UserData.ChildNodes | Select-Object -First 1
    $msg = ""
    if ($u) { $msg = (@($u.ChildNodes | ForEach-Object { $_.Name + "=" + $_.InnerText }) -join " ") }
    "level=" + $e.LevelDisplayName + " " + $msg
}
$lsm = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
Add-Events "LSM" ($common + @{ LogName = $lsm; Id = @(21, 22, 23, 24, 25) }) {
    param($xml, $e)
    $u = $xml.Event.UserData.ChildNodes | Select-Object -First 1
    $msg = ""
    if ($u) { $msg = (@($u.ChildNodes | ForEach-Object { $_.Name + "=" + $_.InnerText }) -join " ") }
    $msg
}

$timeline = @($rows | Where-Object { $_.Detail } | Sort-Object Time)
$timeline | Export-Csv -Path (Join-Path $OutDir "timeline.csv") -NoTypeInformation -Encoding UTF8

Say "## Timeline (UTC, oldest first)"
if ($timeline.Count -eq 0) {
    Say "  no event in the window (is the Remote Desktop listener on? are the channels enabled?)"
}
foreach ($r in $timeline) {
    Say ("  {0}  {1,-8} {2,-5} {3}" -f $r.Time, $r.Source, $r.Id, $r.Detail)
}
Say ""

$failed = @($timeline | Where-Object { $_.Source -eq "Security" -and $_.Id -eq 4625 }).Count
$authed = @($timeline | Where-Object { $_.Source -eq "RCM" -and $_.Id -eq 1149 }).Count
$sessions = @($timeline | Where-Object { $_.Source -eq "LSM" -and $_.Id -eq 21 }).Count
Say "## Counts"
Say ("  4625 failed logon (types 3/10): " + $failed)
Say ("  1149 RCM authentication succeeded: " + $authed)
Say ("  21 LSM session logon: " + $sessions)
Say ""
Say "## How to read it (NLA setting: $nlaText)"
Say "  One wrong-password attempt and one good one should give: 4625 x1, 1149 x1, 21 x1."
Say "  1149 x2 (one of them right after the 4625, with no session 21) means the refused"
Say "  attempt is also logged as 1149: the success-after-failures rule would count it."
Say "  Keep the timeline.csv and this summary for the #700 discussion."
Say ""
Say ("Files: " + $OutDir)
