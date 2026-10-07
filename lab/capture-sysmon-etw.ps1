<#
.SYNOPSIS
    Passive lab capture for ADR-0026 follow-up 1 (#715): what the Sysmon channel
    carries, and whether two driver-free ETW providers can replace Sysmon ids 8
    and 10 for a non-PPL consumer.

.DESCRIPTION
    Elevated, read-only with respect to the host's security tooling: it never
    installs, configures, starts or stops Sysmon, never touches LSASS on purpose
    and attacks nothing. It only reads event logs and runs two short, uniquely
    named ETW sessions (`syncap-*`) that it stops itself.

      A. Sysmon channel. Lists every event log whose name contains "Sysmon"
         (name, enabled, record count, size), the Sysmon services present, and
         for the newest -SysmonSample events: count per event id, the data
         field names seen per id, and the observed events/s per id. Raw sample
         exported as XML, so it can become a golden fixture.

      B. Driver-free candidates. For each of Microsoft-Windows-Kernel-Process
         (thread start, keyword -ThreadKeyword) and
         Microsoft-Windows-Kernel-Audit-API-Calls (OpenProcess), whether the
         provider is registered, whether a non-PPL real-time session can enable
         it, and what arrives during an idle window and a busy window: events
         per id, events/s, the data field names per id. The busy window runs a
         benign load (short-lived processes, file reads, Get-Process).

    Everything lands under -OutDir (summary.txt is the file to read; the .etl
    files are kept for a second look with tracerpt or WPA).

    ASCII only, stock Windows PowerShell 5.1 (#433).

.PARAMETER OutDir
    Where to write. Default: .\sysmon-capture-<timestamp>.
.PARAMETER IdleSeconds
    Length of the idle window per provider. Default 60.
.PARAMETER BusySeconds
    Length of the busy window per provider. Default 60.
.PARAMETER SysmonSample
    How many of the newest Sysmon events to analyse and export. Default 5000.
.PARAMETER ThreadKeyword
    Keyword mask for Kernel-Process. Default 0x20 (THREAD).
.PARAMETER SkipSysmon
    Skip phase A (no Sysmon on this host).
.PARAMETER SkipEtw
    Skip phase B.
#>
[CmdletBinding()]
param(
    [string]$OutDir = "",
    [int]$IdleSeconds = 60,
    [int]$BusySeconds = 60,
    [int]$SysmonSample = 5000,
    [string]$ThreadKeyword = "0x20",
    [switch]$SkipSysmon,
    [switch]$SkipEtw
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated PowerShell (ETW sessions need it)."
}

if (-not $OutDir) {
    $OutDir = Join-Path (Get-Location) ("sysmon-capture-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$summary = Join-Path $OutDir "summary.txt"

function Say {
    param([string]$Text = "")
    Write-Host $Text
    Add-Content -Path $summary -Value $Text
}

function Get-EventStats {
    # Streams an XML event dump (wevtutil / tracerpt) one <Event> at a time:
    # count per id, field names per id, first and last timestamp.
    param([string]$XmlPath)
    $ids = @{}
    $fields = @{}
    $first = $null
    $last = $null
    $buffer = New-Object System.Text.StringBuilder
    $reader = New-Object System.IO.StreamReader($XmlPath)
    try {
        while (($line = $reader.ReadLine()) -ne $null) {
            [void]$buffer.Append($line)
            if ($line.Contains("</Event>")) {
                $text = $buffer.ToString()
                [void]$buffer.Clear()
                $m = [regex]::Match($text, "<EventID[^>]*>(\d+)</EventID>")
                if (-not $m.Success) { continue }
                $id = $m.Groups[1].Value
                $ids[$id] = 1 + [int]$ids[$id]
                if (-not $fields.ContainsKey($id)) { $fields[$id] = @{} }
                foreach ($f in [regex]::Matches($text, "<Data Name=['""]([^'""]+)['""]")) {
                    $fields[$id][$f.Groups[1].Value] = $true
                }
                $t = [regex]::Match($text, "SystemTime=['""]([^'""]+)['""]")
                if ($t.Success) {
                    $stamp = [datetime]::Parse($t.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
                    if (-not $first -or $stamp -lt $first) { $first = $stamp }
                    if (-not $last -or $stamp -gt $last) { $last = $stamp }
                }
            }
        }
    }
    finally {
        $reader.Close()
    }
    return @{ Ids = $ids; Fields = $fields; First = $first; Last = $last }
}

function Write-EventStats {
    param($Stats, [double]$Seconds)
    if ($Stats.Ids.Count -eq 0) {
        Say "    no events"
        return
    }
    if ($Seconds -le 0 -and $Stats.First -and $Stats.Last) {
        $Seconds = [Math]::Max(1.0, ($Stats.Last - $Stats.First).TotalSeconds)
    }
    foreach ($id in ($Stats.Ids.Keys | Sort-Object { [int]$_ })) {
        $count = $Stats.Ids[$id]
        $rate = if ($Seconds -gt 0) { [Math]::Round($count / $Seconds, 2) } else { 0 }
        Say ("    id {0,-5} {1,8} events  {2,8} /s  fields: {3}" -f $id, $count, $rate,
            (($Stats.Fields[$id].Keys | Sort-Object) -join ", "))
    }
}

Say "# Sysmon / driver-free candidate capture (ADR-0026, #715)"
Say ("Date (UTC): " + (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))
Say ("Host: " + $env:COMPUTERNAME)
$os = Get-CimInstance Win32_OperatingSystem
Say ("OS: " + $os.Caption + " build " + $os.BuildNumber + " (" + $os.OSArchitecture + ")")
Say ""

# ---- A. Sysmon channel ---------------------------------------------------------------
if (-not $SkipSysmon) {
    Say "## A. Sysmon channel"
    $svc = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Sysmon*" -or $_.DisplayName -like "*Sysmon*" })
    if ($svc.Count -eq 0) { Say "  services: none matching *Sysmon*" }
    foreach ($s in $svc) { Say ("  service: " + $s.Name + " (" + $s.DisplayName + ") " + $s.Status) }

    $logs = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.LogName -like "*Sysmon*" })
    if ($logs.Count -eq 0) {
        Say "  event logs: none matching *Sysmon* (nothing to capture; use -SkipSysmon next time)"
    }
    foreach ($log in $logs) {
        Say ("  log: " + $log.LogName + "  enabled=" + $log.IsEnabled + "  records=" + $log.RecordCount +
            "  size=" + $log.FileSize + "  max=" + $log.MaximumSizeInBytes)
        if (-not $log.IsEnabled -or -not $log.RecordCount) { continue }
        $safe = ($log.LogName -replace "[^A-Za-z0-9]", "_")
        $xml = Join-Path $OutDir ("sysmon-" + $safe + ".xml")
        # wevtutil, not Get-WinEvent: it writes the raw <Event> XML, the form a fixture needs.
        & wevtutil.exe qe $log.LogName /c:$SysmonSample /rd:true /f:xml | Out-File -FilePath $xml -Encoding utf8
        if ($LASTEXITCODE -ne 0) { Say ("  wevtutil failed for " + $log.LogName + " (exit " + $LASTEXITCODE + ")"); continue }
        $stats = Get-EventStats -XmlPath $xml
        $span = if ($stats.First -and $stats.Last) { [Math]::Round(($stats.Last - $stats.First).TotalSeconds, 1) } else { 0 }
        Say ("  sample: " + (($stats.Ids.Values | Measure-Object -Sum).Sum) + " events over " + $span + " s, raw XML in " + $xml)
        Write-EventStats -Stats $stats -Seconds 0
    }
    Say ""
}

# ---- B. Driver-free candidates ---------------------------------------------------------
function Start-BusyLoad {
    # Benign: short-lived processes, file reads, and process enumeration (which opens
    # handles on other processes the way an inventory tool does). Nothing is attacked.
    param([int]$Seconds)
    $dir = Join-Path $env:TEMP "syncap-load"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $end = (Get-Date).AddSeconds($Seconds)
    $n = 0
    while ((Get-Date) -lt $end) {
        & cmd.exe /c ver | Out-Null
        $file = Join-Path $dir ("f" + ($n % 50) + ".txt")
        Set-Content -Path $file -Value ("line " + $n)
        [void](Get-Content -Path $file)
        [void](Get-Process | Select-Object -Property Id, ProcessName, Path)
        $n++
    }
    Remove-Item -Recurse -Force -Path $dir -ErrorAction SilentlyContinue
    return $n
}

function Test-ProviderRegistered {
    param([string]$Name)
    $list = & logman.exe query providers 2>&1 | Out-String
    return $list.Contains($Name)
}

function Invoke-EtwWindow {
    param([string]$Provider, [string]$Keyword, [string]$Label, [int]$Seconds, [bool]$Busy)
    $name = "syncap-" + $Label + "-" + (Get-Random -Maximum 99999)
    $etl = Join-Path $OutDir ($Label + ".etl")
    $xml = Join-Path $OutDir ($Label + ".xml")
    $started = $false
    try {
        & logman.exe create trace $name -ets -p $Provider $Keyword 0xFF -o $etl -bs 64 -nb 16 64 -max 512 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Say ("    could not start a session for " + $Provider + " (logman exit " + $LASTEXITCODE + "): not enabled")
            return
        }
        $started = $true
        $t0 = Get-Date
        if ($Busy) {
            $loops = Start-BusyLoad -Seconds $Seconds
            Say ("    busy load: " + $loops + " iterations")
        }
        else {
            Start-Sleep -Seconds $Seconds
        }
        $elapsed = ((Get-Date) - $t0).TotalSeconds
    }
    finally {
        if ($started) { & logman.exe stop $name -ets 2>&1 | Out-Null }
    }
    if (-not (Test-Path $etl)) { Say "    no ETL written"; return }
    & tracerpt.exe $etl -of XML -o $xml -y -summary (Join-Path $OutDir ($Label + "-summary.txt")) -report (Join-Path $OutDir ($Label + "-report.xml")) 2>&1 | Out-Null
    if (-not (Test-Path $xml)) { Say "    tracerpt produced no XML"; return }
    $stats = Get-EventStats -XmlPath $xml
    Write-EventStats -Stats $stats -Seconds $elapsed
}

if (-not $SkipEtw) {
    Say "## B. Driver-free candidates (non-PPL real-time session)"
    $candidates = @(
        @{ Provider = "Microsoft-Windows-Kernel-Process"; Keyword = $ThreadKeyword; Tag = "kproc"; Why = "thread start (Sysmon 8)" },
        @{ Provider = "Microsoft-Windows-Kernel-Audit-API-Calls"; Keyword = "0xFFFFFFFFFFFFFFFF"; Tag = "kaudit"; Why = "OpenProcess (Sysmon 10)" }
    )
    foreach ($c in $candidates) {
        Say ("  " + $c.Provider + "  [" + $c.Why + "]  keyword " + $c.Keyword)
        Say ("    registered: " + (Test-ProviderRegistered -Name $c.Provider))
        Say ("  -- idle " + $IdleSeconds + " s")
        Invoke-EtwWindow -Provider $c.Provider -Keyword $c.Keyword -Label ($c.Tag + "-idle") -Seconds $IdleSeconds -Busy $false
        Say ("  -- busy " + $BusySeconds + " s")
        Invoke-EtwWindow -Provider $c.Provider -Keyword $c.Keyword -Label ($c.Tag + "-busy") -Seconds $BusySeconds -Busy $true
        Say ""
    }
    Say "Leftover syncap-* sessions (should be none):"
    $left = & logman.exe query -ets 2>&1 | Out-String
    $found = @($left -split "`r?`n" | Where-Object { $_ -match "^syncap-" })
    if ($found.Count -eq 0) { Say "  none (or logman cannot list; check Get-EtwTraceSession)" } else { $found | ForEach-Object { Say ("  " + $_) } }
    Say ""
}

Say ("Done. Read " + $summary + "; keep the .etl and .xml files for the ADR-0026 capture report.")
