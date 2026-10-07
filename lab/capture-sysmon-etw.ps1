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
         per id, events/s, the data field names per id, and the session's own
         loss counters. The busy window runs a benign load (bursts of
         short-lived processes, file reads, a process listing every few
         rounds). The sessions write to a file (logman -o), not to a real-time
         consumer: this shows that a non-PPL session can enable the provider
         and at what volume, not how a real-time consumer keeps up.

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

function Invoke-Tool {
    # Runs a native tool and returns its exit code and output. Windows PowerShell 5.1
    # turns every stderr line of `2>&1` into a terminating error under
    # $ErrorActionPreference = "Stop", so the tool runs under "Continue" and the
    # caller tests the exit code.
    param([string]$FilePath, [string[]]$Arguments = @())
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $FilePath @Arguments 2>&1 | ForEach-Object { "$_" }
        return @{ Exit = $LASTEXITCODE; Output = @($output) }
    }
    finally {
        $ErrorActionPreference = $saved
    }
}

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
    # Benign: bursts of short-lived processes, file reads, and a process listing every
    # few rounds (it opens handles on other processes the way an inventory tool does).
    # Nothing is attacked. Get-Process is slow, so it runs on a fraction of the rounds.
    param([int]$Seconds)
    $dir = Join-Path $env:TEMP "syncap-load"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $end = (Get-Date).AddSeconds($Seconds)
    $n = 0
    while ((Get-Date) -lt $end) {
        1..25 | ForEach-Object { & cmd.exe /c ver | Out-Null }
        $file = Join-Path $dir ("f" + ($n % 50) + ".txt")
        Set-Content -Path $file -Value ("line " + $n)
        [void](Get-Content -Path $file)
        if (($n % 5) -eq 0) { [void](Get-Process | Select-Object -Property Id, ProcessName, Path) }
        $n++
    }
    Remove-Item -Recurse -Force -Path $dir -ErrorAction SilentlyContinue
    return $n
}

function Test-ProviderRegistered {
    param([string]$Name)
    # Whole-name match on the name column: "Kernel-Process" must not match
    # "Kernel-Processor-Power".
    $result = Invoke-Tool -FilePath "logman.exe" -Arguments @("query", "providers")
    if ($result.Exit -ne 0) { return "unknown (logman exit " + $result.Exit + ")" }
    foreach ($line in $result.Output) {
        $m = [regex]::Match($line, "^\s*(\S.*?)\s+\{[0-9A-Fa-f-]{36}\}\s*$")
        if ($m.Success -and $m.Groups[1].Value -ieq $Name) { return $true }
    }
    return $false
}

function Invoke-EtwWindow {
    param([string]$Provider, [string]$Keyword, [string]$Label, [int]$Seconds, [bool]$Busy)
    $name = "syncap-" + $Label + "-" + (Get-Random -Maximum 99999)
    $etl = Join-Path $OutDir ($Label + ".etl")
    $xml = Join-Path $OutDir ($Label + ".xml")
    $started = $false
    try {
        $create = Invoke-Tool -FilePath "logman.exe" -Arguments @("create", "trace", $name, "-ets", "-p", $Provider, $Keyword, "0xFF", "-o", $etl, "-bs", "64", "-nb", "16", "64", "-max", "512")
        if ($create.Exit -ne 0) {
            Say ("    could not start a session for " + $Provider + " (logman exit " + $create.Exit + "): not enabled")
            foreach ($line in $create.Output) { Say ("      " + $line) }
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
        if ($started) { [void](Invoke-Tool -FilePath "logman.exe" -Arguments @("stop", $name, "-ets")) }
    }
    if (-not (Test-Path $etl)) { Say "    no ETL written"; return }
    $report = Invoke-Tool -FilePath "tracerpt.exe" -Arguments @($etl, "-of", "XML", "-o", $xml, "-y", "-summary", (Join-Path $OutDir ($Label + "-summary.txt")), "-report", (Join-Path $OutDir ($Label + "-report.xml")))
    if ($report.Exit -ne 0 -or -not (Test-Path $xml)) { Say ("    tracerpt failed (exit " + $report.Exit + "): no XML"); return }
    $stats = Get-EventStats -XmlPath $xml
    Write-EventStats -Stats $stats -Seconds $elapsed
    $lost = @(Select-String -Path $xml -Pattern 'Name="(EventsLost|BuffersLost)">\s*(\d+)' -AllMatches |
        ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value + "=" + $_.Groups[2].Value })
    if ($lost.Count -gt 0) { Say ("    session losses: " + ($lost -join " ")) }
}

if (-not $SkipEtw) {
    Say "## B. Driver-free candidates (non-PPL session, file mode)"
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
    $listing = Invoke-Tool -FilePath "logman.exe" -Arguments @("query", "-ets")
    $found = @($listing.Output | Where-Object { $_ -match "^syncap-" })
    if ($found.Count -eq 0) { Say "  none (or logman cannot list; check Get-EtwTraceSession)" } else { $found | ForEach-Object { Say ("  " + $_) } }
    Say ""
}

Say ("Done. Read " + $summary + "; keep the .etl and .xml files for the ADR-0026 capture report.")
