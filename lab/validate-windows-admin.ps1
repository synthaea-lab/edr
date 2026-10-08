<#
.SYNOPSIS
    Elevated live validation for the Windows ETW sensor: #408 (orphaned ETW
    sessions), #489 (8.3 short paths), #442 point 2 (mark-of-the-web removal).

.DESCRIPTION
    Six phases, each skippable, with results written under -OutDir:

      A. #408 cleanup. Leaves one real orphan (agent killed with -Force) plus
         two synthetic `wtrace-` sessions, starts the agent, and checks that
         every one of them is stopped, that events flow, and that the sweep's
         own logman.exe children raise no SELF-SPAWN alert (#463).

      B. #408 root cause. #408 saw a new session receive zero events while
         orphans were running, without proving the orphans were the cause.
         One documented mechanism fits: a manifest provider can be enabled by
         at most 8 sessions at once (EnableTraceEx2), and a real-time orphan
         keeps its providers enabled. For each N in -ProbeCounts this starts N
         real-time sessions enabling the agent's providers under a name the
         sweep does NOT touch (`synthaea408-probe-*`), starts the agent, and
         records which event types still arrive. The host's own enablers per
         provider are recorded first, since they count toward the same limit.

      C. #489. Needs an agent built with the #489 fix (PR #492). Writes
         mark-of-the-web streams through both the 8.3 short path and the long
         path of the same files, plus a curl.exe download into the short
         directory, then checks one FileQuarantine per file, no `~` in any
         event path, and a long-form path in the T1105 alert.

      D. #442 point 2. No agent: a raw Kernel-File trace (logman, file mode)
         around Unblock-File and `Remove-Item -Stream Zone.Identifier`, to see
         which events and fields a mark removal produces before wiring a rule.

      E. #442 end to end. Marks two copies of whoami.exe, removes one mark
         with Unblock-File and the other with `Remove-Item -Stream`, runs
         both, and checks one `file_delete` of each stream and one T1553.005
         alert per file. Skipped with -SkipMarkRemoval, like D.

      F. #708. Runs the ignored Kernel-File keyword-mask integration test as
         administrator. It checks that mask 0x1480 delivers only event IDs
         12, 26, and 30, then proves the assertion rejects 0x1E80.

    The verdicts are printed and saved to summary.txt; everything else (agent
    logs, events.jsonl, alerts.ndjson, the raw D trace) stays in -OutDir.

.NOTES
    Run from an elevated Windows PowerShell 5.1+ prompt, with no other agent
    running. For the full validation, build agent.exe first:
        cargo build --release -p agent        (from the branch under test)
        powershell -ExecutionPolicy Bypass -File lab\validate-windows-admin.ps1

    To run only the #708 ETW mask phase, skip the agent-dependent phases:
        powershell -ExecutionPolicy Bypass -File lab\validate-windows-admin.ps1 -SkipOrphans -SkipRootCause -SkipLongPath -SkipMarkRemoval

    About 6 minutes with the default -ProbeCounts, plus the short #708 ETW
    test. Stops only what it created plus `wtrace-` sessions, which are the
    agent's own by construction.
#>
[CmdletBinding()]
param(
    [string]$AgentExe = "",
    [string]$OutDir = "",
    [int[]]$ProbeCounts = @(0, 2, 6, 7, 8),
    [int]$MarkCount = 10,
    [switch]$SkipOrphans,
    [switch]$SkipRootCause,
    [switch]$SkipLongPath,
    [switch]$SkipMarkRemoval,
    [switch]$SkipKernelFileMask
)

# Defaults resolved here, not in param(): Windows PowerShell 5.1 leaves
# $PSScriptRoot empty while it evaluates param() defaults.
if (-not $AgentExe) { $AgentExe = Join-Path $PSScriptRoot "..\target\release\agent.exe" }
if (-not $OutDir) {
    $OutDir = Join-Path $PSScriptRoot ("..\target\lab-validation\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
. (Join-Path $PSScriptRoot "scenarios\common.ps1")

# The agent's ETW providers (crates/sensors/windows/etw/src/providers.rs).
$AgentProviders = [ordered]@{
    "Kernel-Process"  = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"
    "Kernel-Network"  = "7dd42a49-5329-4832-8dfd-43d979153a88"
    "Kernel-File"     = "edd08927-9cc4-4e65-b970-c2560fb5c289"
    "DNS-Client"      = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D"
    "Kernel-Registry" = "70EB4F03-C1DE-4F73-A051-33D13D5413BD"
    "PowerShell"      = "A0C1853B-5C40-4B15-8766-3CF1C58F985A"
    "WMI-Activity"    = "1418EF04-B0B4-4623-BF7E-D74AB47BBDAA"
    "DotNETRuntime"   = "e13c0d23-ccbc-4e12-931b-d9cc2eee27e4"
    "SMBClient"       = "988C59C5-0A1C-45B6-A555-0C62276E327D"
}
$ProbePrefix = "synthaea408-probe-"
$CapturePrefix = "synthaea442-"
$AgentPrefix = "wtrace-"
$KernelFileMaskPrefix = "synthaea-kf-mask-"
$Results = New-Object System.Collections.ArrayList
$Current = $null
$KernelFileMaskSession = $null
$KernelFileMaskNeedsCleanup = $false

# -- Output ------------------------------------------------------------------

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

function Add-Result {
    param([string]$Check, [ValidateSet("PASS", "FAIL", "INFO", "SKIP")][string]$Verdict, [string]$Detail)
    $color = @{ PASS = "Green"; FAIL = "Red"; INFO = "Gray"; SKIP = "Yellow" }[$Verdict]
    Write-Host ("  [{0}] {1}: {2}" -f $Verdict, $Check, $Detail) -ForegroundColor $color
    [void]$Results.Add([pscustomobject]@{ Verdict = $Verdict; Check = $Check; Detail = $Detail })
}

# -- ETW sessions --------------------------------------------------------------

function Get-EtsSessionNames {
    # First token of each line: the session name column. Header and footer
    # lines are locale text and never match the prefixes this script filters on.
    # Windows PowerShell 5.1 turns a redirected native stderr line into a
    # terminating error under "Stop"; the exit code is checked instead.
    $ErrorActionPreference = "Continue"
    $out = & logman query -ets 2>&1
    if ($LASTEXITCODE -ne 0) { throw "logman query -ets failed: $out" }
    $out | ForEach-Object { ("$_".Trim() -split '\s+')[0] } | Where-Object { $_ }
}

function Get-EtsSessions([string]$Prefix) {
    @(Get-EtsSessionNames | Where-Object { $_.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase) })
}

function Stop-EtsSessions([string]$Prefix) {
    foreach ($name in (Get-EtsSessions $Prefix)) {
        Invoke-NativeCleanup "ETW session $name" logman.exe @("stop", $name, "-ets")
    }
}

function Get-ProviderFile {
    $path = Join-Path $OutDir "agent-providers.txt"
    if (-not (Test-Path $path)) {
        $AgentProviders.Values | ForEach-Object { "{$_} 0xffffffffffffffff 0x5" } |
            Set-Content -LiteralPath $path -Encoding Ascii
    }
    $path
}

function New-RealtimeSession([string]$Name) {
    # Real-time, no consumer: the same shape as a session orphaned by a killed agent.
    Invoke-Native logman.exe @("start", $Name, "-pf", (Get-ProviderFile), "-rt", "-ets")
}

function Get-ProviderEnablers {
    # How many running sessions already enable each agent provider. They count
    # toward the per-provider session limit the root-cause phase probes.
    $ErrorActionPreference = "Continue"
    $counts = [ordered]@{}
    foreach ($key in $AgentProviders.Keys) { $counts[$key] = 0 }
    foreach ($session in (Get-EtsSessionNames)) {
        $detail = (& logman query $session -ets 2>$null) -join "`n"
        if ($LASTEXITCODE -ne 0) { continue }
        foreach ($key in $AgentProviders.Keys) {
            if ($detail -match [regex]::Escape($AgentProviders[$key])) { $counts[$key]++ }
        }
    }
    $counts
}

# -- Agent -------------------------------------------------------------------

function Start-LabAgent([string]$Tag) {
    $dir = Join-Path $OutDir $Tag
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $agentArgs = @("--config", "`"$ConfigPath`"", "run",
        "--alerts", "`"$dir\alerts.ndjson`"", "--events", "`"$dir\events.jsonl`"")
    $proc = Start-Process -FilePath $AgentExe -ArgumentList $agentArgs -WorkingDirectory $dir `
        -RedirectStandardOutput "$dir\stdout.log" -RedirectStandardError "$dir\stderr.log" `
        -WindowStyle Hidden -PassThru
    $script:Current = [pscustomobject]@{
        Process = $proc; Dir = $dir; Started = Get-Date
        Events = "$dir\events.jsonl"; Alerts = "$dir\alerts.ndjson"
    }
    $script:Current
}

function Wait-AgentEvents($Agent, [int]$TimeoutSec = 30) {
    # Ready once the first event lands (the pid store is seeded and the trace runs).
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ($Agent.Process.HasExited) { return $false }
        if ((Test-Path $Agent.Events) -and (Get-Item $Agent.Events).Length -gt 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    $false
}

function Stop-LabAgent($Agent) {
    if ($Agent -and -not $Agent.Process.HasExited) {
        Stop-Process -Id $Agent.Process.Id -Force
        $Agent.Process.WaitForExit(10000) | Out-Null
    }
    $script:Current = $null
}

function Get-AgentLog($Agent) {
    (@("stdout.log", "stderr.log") | ForEach-Object {
        $path = Join-Path $Agent.Dir $_
        if (Test-Path $path) { Get-Content -LiteralPath $path -Raw }
    }) -join "`n"
}

function Get-EventTypeCounts($Agent) {
    $counts = @{}
    if (Test-Path $Agent.Events) {
        Select-String -LiteralPath $Agent.Events -Pattern '^\{"type":"([a-z_]+)"' | ForEach-Object {
            $type = $_.Matches[0].Groups[1].Value
            $counts[$type] = 1 + [int]$counts[$type]
        }
    }
    $counts
}

function Format-Counts($Counts) {
    if ($Counts.Count -eq 0) { return "(none)" }
    ($Counts.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join " "
}

function Get-Alerts($Agent) {
    if (-not (Test-Path $Agent.Alerts)) { return @() }
    @(Get-Content -LiteralPath $Agent.Alerts | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
}

function Invoke-Triggers($Agent, [string]$Marker) {
    # One exec and one file write the agent must see, tagged so they can be found.
    Start-Process -FilePath cmd.exe -ArgumentList @("/c", "echo", $Marker) -WindowStyle Hidden -Wait
    Set-Content -LiteralPath (Join-Path $Agent.Dir "$Marker.txt") -Value $Marker -Encoding Ascii
}

function Test-Marker($Agent, [string]$Marker, [string]$Type) {
    if (-not (Test-Path $Agent.Events)) { return $false }
    $hit = Select-String -LiteralPath $Agent.Events -SimpleMatch -Pattern $Marker |
        Where-Object { $_.Line.StartsWith("{`"type`":`"$Type`"") } | Select-Object -First 1
    [bool]$hit
}

function Test-SensorFailed([string]$Log) {
    $Log -match "ETW sensor failed" -or $Log -match "produced no events for 30s"
}

function Invoke-KernelFileMaskTest([string]$Mask) {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $env:SYNTHAEA_KERNEL_FILE_MASK = $Mask
        $output = & cargo test -p sensor-windows --test kernel_file_keyword_mask -- --ignored --exact kernel_file_keyword_mask_respects_the_requested_event_ids --nocapture 2>&1
        $exitCode = $LASTEXITCODE
    } catch {
        $output = @($_.Exception.Message)
        $exitCode = 1
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    foreach ($line in @($output)) {
        $lineText = "$line"
        Write-Host $lineText
        if ($lineText -match "KERNEL_FILE_MASK_SESSION=(\S+)") {
            $candidate = $Matches[1]
            if ($candidate.StartsWith($KernelFileMaskPrefix, [StringComparison]::Ordinal)) {
                $script:KernelFileMaskSession = $candidate
            }
        }
    }
    if ((@($output) -join "`n") -notmatch "test result:") {
        $script:KernelFileMaskNeedsCleanup = [bool]$script:KernelFileMaskSession
    }
    [pscustomobject]@{ ExitCode = $exitCode; Output = (@($output) -join "`n") }
}

# -- Setup -------------------------------------------------------------------

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell: the ETW kernel providers need Administrator."
}
if (-not ($SkipOrphans -and $SkipRootCause -and $SkipLongPath -and $SkipMarkRemoval) -and -not (Test-Path $AgentExe)) {
    throw "agent.exe not found at $AgentExe - build it first (cargo build --release -p agent) or pass -AgentExe"
}
$needsAgent = -not ($SkipOrphans -and $SkipRootCause -and $SkipLongPath -and $SkipMarkRemoval)
if ($needsAgent) { $AgentExe = (Resolve-Path $AgentExe).Path }
if (Get-Process -Name "agent" -ErrorAction SilentlyContinue) {
    throw "An agent.exe is already running; stop it first (its ETW session would be swept by this test)."
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$ConfigPath = Join-Path $OutDir "agent.toml"
@"
schema_version = 1

[server]
control_plane_url = "https://cp.lab.invalid"
mtls_cert = '$OutDir\certs\client.crt'
mtls_key = '$OutDir\certs\client.key'
mtls_passphrase = "envvar:SYNTHAEA_MTLS_PASSPHRASE"
offline_fallback = true

[log]
dir = '$OutDir\logs'
level = "info"
max_mb = 64

[storage]
state_dir = '$OutDir\state'
spool_max_mb = 64

[ipc]
endpoint = '\\.\pipe\synthaea-lab-validation'

[resources]
worker_threads = 0
max_reconnect_backoff_ms = 60000
"@ | Set-Content -LiteralPath $ConfigPath -Encoding Ascii

if ($needsAgent) {
    Write-Host "agent:  $AgentExe ($((Get-Item $AgentExe).LastWriteTime))"
} else {
    Write-Host "agent:  not needed"
}
Write-Host "output: $OutDir"

$LabDirs = @()
try {
    $preexisting = Get-EtsSessions $AgentPrefix
    Add-Result "pre-existing wtrace- sessions" "INFO" "$($preexisting.Count) before the run: $($preexisting -join ', ')"
    Stop-EtsSessions $AgentPrefix
    Stop-EtsSessions $ProbePrefix

    # -- A. #408: every orphan is stopped -----------------------------------
    if (-not $SkipOrphans) {
        Write-Section "A. #408 orphan cleanup"
        $seed = Start-LabAgent "A0-make-orphan"
        if (-not (Wait-AgentEvents $seed)) { throw "the agent produced no events in 30s; see $($seed.Dir)" }
        Stop-LabAgent $seed
        $realOrphans = Get-EtsSessions $AgentPrefix
        New-RealtimeSession "${AgentPrefix}lab408-a"
        New-RealtimeSession "${AgentPrefix}lab408-b"
        $orphans = Get-EtsSessions $AgentPrefix
        Add-Result "orphans before start" "INFO" "$($orphans.Count) ($($realOrphans.Count) left by a killed agent): $($orphans -join ', ')"

        $agent = Start-LabAgent "A1-sweep"
        $ready = Wait-AgentEvents $agent
        Invoke-Triggers $agent "synthaea408-sweep"
        Start-Sleep -Seconds 35
        $running = Get-EtsSessions $AgentPrefix
        $survivors = @($orphans | Where-Object { $running -contains $_ })
        Stop-LabAgent $agent
        $log = Get-AgentLog $agent
        $stopped = ([regex]::Matches($log, "orphaned ETW session stopped")).Count
        $logmanAlerts = @(Get-Alerts $agent | Where-Object { $_.technique -eq "T1059" -and $_.message -match "logman" })

        if ($survivors.Count -eq 0 -and $stopped -ge $orphans.Count) {
            Add-Result "#408 every orphan stopped" "PASS" "$stopped stopped, $($running.Count) wtrace- session(s) left (the new agent's own)"
        } else {
            Add-Result "#408 every orphan stopped" "FAIL" "survivors: $($survivors -join ', '); 'stopped' log lines: $stopped"
        }
        if ($ready -and -not (Test-SensorFailed $log) -and (Test-Marker $agent "synthaea408-sweep" "exec")) {
            Add-Result "#408 events flow after the sweep" "PASS" (Format-Counts (Get-EventTypeCounts $agent))
        } else {
            Add-Result "#408 events flow after the sweep" "FAIL" "ready=$ready sensor-failed=$(Test-SensorFailed $log) types: $(Format-Counts (Get-EventTypeCounts $agent))"
        }
        if ($logmanAlerts.Count -eq 0) {
            Add-Result "#463 no SELF-SPAWN on the sweep's logman.exe" "PASS" "no T1059 alert mentioning logman"
        } else {
            Add-Result "#463 no SELF-SPAWN on the sweep's logman.exe" "FAIL" $logmanAlerts[0].message
        }
        Stop-EtsSessions $AgentPrefix
    }

    # -- B. #408: can concurrent sessions blind a new one? ------------------
    if (-not $SkipRootCause) {
        Write-Section "B. #408 root cause (per-provider session limit)"
        $enablers = Get-ProviderEnablers
        Add-Result "host sessions already enabling each provider" "INFO" (($enablers.GetEnumerator() | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join " ")
        foreach ($n in $ProbeCounts) {
            $refused = @()
            for ($i = 1; $i -le $n; $i++) {
                # A refusal is itself the evidence this phase looks for.
                try { New-RealtimeSession "$ProbePrefix$i" } catch { $refused += "probe $i ($($_.Exception.Message))" }
            }
            if ($refused.Count -gt 0) { Add-Result "probes=$n refused" "INFO" ($refused -join "; ") }
            $agent = Start-LabAgent "B-probes-$n"
            $ready = Wait-AgentEvents $agent
            $marker = "synthaea408-probe$n"
            Invoke-Triggers $agent $marker
            Start-Sleep -Seconds 5
            Invoke-Triggers $agent "$marker-late"
            $elapsed = ((Get-Date) - $agent.Started).TotalSeconds
            if ($elapsed -lt 40) { Start-Sleep -Seconds ([int](40 - $elapsed)) }
            Stop-LabAgent $agent
            $log = Get-AgentLog $agent
            Stop-EtsSessions $ProbePrefix
            Stop-EtsSessions $AgentPrefix
            $sawExec = (Test-Marker $agent $marker "exec") -or (Test-Marker $agent "$marker-late" "exec")
            $sawFile = (Test-Marker $agent $marker "file_open") -or (Test-Marker $agent "$marker-late" "file_open")
            Add-Result "probes=$n" "INFO" ("ready={0} exec-seen={1} file-seen={2} sensor-failed={3} types: {4}" -f `
                $ready, $sawExec, $sawFile, (Test-SensorFailed $log), (Format-Counts (Get-EventTypeCounts $agent)))
        }
    }

    # -- C. #489: one file, one path --------------------------------------
    if (-not $SkipLongPath) {
        Write-Section "C. #489 8.3 short paths"
        $fso = New-Object -ComObject Scripting.FileSystemObject
        $labDir = Join-Path $env:TEMP ("synthaea 489 lab " + (Get-Random -Maximum 99999))
        New-Item -ItemType Directory -Path $labDir | Out-Null
        $LabDirs += $labDir
        $shortDir = $fso.GetFolder($labDir).ShortPath
        if ($shortDir -eq $labDir -or $shortDir -notmatch "~") {
            Add-Result "#489" "SKIP" "the volume generates no 8.3 names for $labDir (fsutil 8dot3name)"
        } else {
            $agent = Start-LabAgent "C-long-path"
            if (-not (Wait-AgentEvents $agent)) { throw "the agent produced no events in 30s; see $($agent.Dir)" }
            for ($i = 1; $i -le $MarkCount; $i++) {
                $long = Join-Path $labDir ("marked long name {0:D2}.exe" -f $i)
                [IO.File]::WriteAllBytes($long, [byte[]](0x4D, 0x5A))
                $short = $fso.GetFile($long).ShortPath
                $zone = "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example.test/lab489/$i.exe`r`n"
                # The same mark through both forms: #489 saw exactly this pair as two files.
                Set-Content -LiteralPath $short -Stream Zone.Identifier -Value $zone -Encoding Ascii
                Set-Content -LiteralPath $long -Stream Zone.Identifier -Value $zone -Encoding Ascii
                Start-Sleep -Milliseconds 200
            }
            $dlLeaf = "downloaded-long-name-489.exe"
            Invoke-Native curl.exe @("-s", "-S", "-o", (Join-Path $shortDir $dlLeaf), "file:///C:/Windows/System32/whoami.exe")
            & (Join-Path $labDir $dlLeaf) | Out-Null
            Start-Sleep -Seconds 8
            Stop-LabAgent $agent

            $labLeaf = Split-Path $labDir -Leaf
            $shortLeaf = Split-Path $shortDir -Leaf
            $events = @(Select-String -LiteralPath $agent.Events -SimpleMatch -Pattern @($labLeaf, $shortLeaf) |
                ForEach-Object { $_.Line | ConvertFrom-Json } |
                Where-Object { $_.path -and ($_.path.IndexOf($labLeaf, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                    $_.path.IndexOf($shortLeaf, [StringComparison]::OrdinalIgnoreCase) -ge 0) })
            $marks = @($events | Where-Object { $_.type -eq "file_quarantine" })
            $shortForm = @($events | Where-Object { $_.path -match "~" })
            if ($marks.Count -eq $MarkCount) {
                Add-Result "#489 one FileQuarantine per file" "PASS" "$($marks.Count) for $MarkCount files, each marked through both forms"
            } else {
                Add-Result "#489 one FileQuarantine per file" "FAIL" "$($marks.Count) for $MarkCount files"
            }
            if ($shortForm.Count -eq 0) {
                Add-Result "#489 no short-form path in events" "PASS" "$($events.Count) events under the lab dir, all long-form"
            } else {
                Add-Result "#489 no short-form path in events" "FAIL" "$($shortForm.Count)/$($events.Count), e.g. $($shortForm[0].type) $($shortForm[0].path)"
            }
            $t1105 = @(Get-Alerts $agent | Where-Object { $_.technique -eq "T1105" -and $_.message -match [regex]::Escape($dlLeaf) })
            if ($t1105.Count -eq 0) {
                Add-Result "#489 T1105 alert quotes the long path" "FAIL" "no T1105 alert for $dlLeaf"
            } elseif (@($t1105 | Where-Object { $_.message -match "~" }).Count -gt 0) {
                Add-Result "#489 T1105 alert quotes the long path" "FAIL" $t1105[0].message
            } else {
                Add-Result "#489 T1105 alert quotes the long path" "PASS" $t1105[0].message
            }
        }
    }

    # -- D. #442 point 2: what a mark removal looks like --------------------
    if (-not $SkipMarkRemoval) {
        Write-Section "D. #442 mark removal (raw Kernel-File trace)"
        $labDir = Join-Path $env:TEMP ("synthaea442lab" + (Get-Random -Maximum 99999))
        New-Item -ItemType Directory -Path $labDir | Out-Null
        $LabDirs += $labDir
        $zone = "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example.test/lab442.exe`r`n"
        $viaUnblock = Join-Path $labDir "unblockfile442.exe"
        $viaStream = Join-Path $labDir "removestream442.exe"
        foreach ($f in @($viaUnblock, $viaStream)) {
            [IO.File]::WriteAllBytes($f, [byte[]](0x4D, 0x5A))
            Set-Content -LiteralPath $f -Stream Zone.Identifier -Value $zone -Encoding Ascii
        }
        $etl = Join-Path $OutDir "D-mark-removal.etl"
        $session = "${CapturePrefix}capture"
        # FILENAME | FILEIO | CREATE | DELETE_PATH | RENAME_SETLINK_PATH | CREATE_NEW_FILE
        Invoke-Native logman.exe @("start", $session, "-p", "{$($AgentProviders['Kernel-File'])}", "0x1CB0", "0x5", "-o", $etl, "-ets")
        try {
            Start-Sleep -Seconds 1
            Unblock-File -LiteralPath $viaUnblock
            Remove-Item -LiteralPath $viaStream -Stream Zone.Identifier
            Start-Sleep -Seconds 2
        } finally {
            Invoke-NativeCleanup "ETW session $session" logman.exe @("stop", $session, "-ets")
        }
        $rows = @(Get-WinEvent -Path $etl -Oldest -ErrorAction SilentlyContinue | ForEach-Object {
            $values = @($_.Properties | ForEach-Object { "$($_.Value)" })
            $joined = $values -join " | "
            if ($joined -match "unblockfile442|removestream442") {
                [pscustomobject]@{
                    Time = $_.TimeCreated.ToString("HH:mm:ss.fff"); Id = $_.Id; Opcode = $_.Opcode
                    Task = $_.TaskDisplayName; Pid = $_.ProcessId; Fields = $joined
                }
            }
        })
        $csv = Join-Path $OutDir "D-mark-removal.csv"
        $rows | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
        $byId = ($rows | Group-Object Id, Task | Sort-Object Name | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join "; "
        Add-Result "#442 events naming the marked files" "INFO" "$($rows.Count) rows ($byId) -> $csv"
        $streamRows = @($rows | Where-Object { $_.Fields -match "Zone\.Identifier" })
        Add-Result "#442 events naming the Zone.Identifier stream" "INFO" (($streamRows | Group-Object Id, Task | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join "; ")
    }

    # -- E. #442 end to end: mark removed, then the file runs ----------------
    if (-not $SkipMarkRemoval) {
        Write-Section "E. #442 mark removal through the agent"
        $labDir = Join-Path $env:TEMP ("synthaea442e2e" + (Get-Random -Maximum 99999))
        New-Item -ItemType Directory -Path $labDir | Out-Null
        $LabDirs += $labDir
        $zone = "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example.test/lab442/run.exe`r`n"
        # A real image, so the exec after the removal is a real process start.
        $viaUnblock = Join-Path $labDir "unblocked442.exe"
        $viaStream = Join-Path $labDir "streamremoved442.exe"
        $agent = Start-LabAgent "E-mark-removal"
        if (-not (Wait-AgentEvents $agent)) { throw "the agent produced no events in 30s; see $($agent.Dir)" }
        foreach ($f in @($viaUnblock, $viaStream)) {
            Copy-Item -LiteralPath "$env:SystemRoot\System32\whoami.exe" -Destination $f
            Set-Content -LiteralPath $f -Stream Zone.Identifier -Value $zone -Encoding Ascii
        }
        Start-Sleep -Seconds 2
        Unblock-File -LiteralPath $viaUnblock
        Remove-Item -LiteralPath $viaStream -Stream Zone.Identifier
        Start-Sleep -Seconds 1
        foreach ($f in @($viaUnblock, $viaStream)) { & $f | Out-Null }
        Start-Sleep -Seconds 8
        Stop-LabAgent $agent

        $alerts = @(Get-Alerts $agent | Where-Object { $_.technique -eq "T1553.005" })
        foreach ($f in @($viaUnblock, $viaStream)) {
            $leaf = Split-Path $f -Leaf
            $deletes = @(Select-String -LiteralPath $agent.Events -SimpleMatch -Pattern $leaf |
                ForEach-Object { $_.Line | ConvertFrom-Json } |
                Where-Object { $_.type -eq "file_delete" -and $_.path -match "Zone\.Identifier" })
            if ($deletes.Count -gt 0) {
                Add-Result "#442 FileDelete of the stream ($leaf)" "PASS" "$($deletes.Count) event(s), e.g. $($deletes[0].meta.comm) $($deletes[0].path)"
            } else {
                Add-Result "#442 FileDelete of the stream ($leaf)" "FAIL" "no file_delete naming $leaf`:Zone.Identifier; see phase D's CSV for what Kernel-File reported"
            }
            $hit = @($alerts | Where-Object { $_.message -match [regex]::Escape($leaf) })
            if ($hit.Count -eq 1) {
                Add-Result "#442 T1553.005 on exec ($leaf)" "PASS" $hit[0].message
            } else {
                Add-Result "#442 T1553.005 on exec ($leaf)" "FAIL" "$($hit.Count) T1553.005 alert(s) for $leaf (expected 1)"
            }
        }
    }

    # -- F. #708: event IDs delivered by the Kernel-File keyword mask -------
    if (-not $SkipKernelFileMask) {
        Write-Section "F. #708 Kernel-File keyword mask"
        $hadKernelFileMask = Test-Path Env:SYNTHAEA_KERNEL_FILE_MASK
        $previousKernelFileMask = $env:SYNTHAEA_KERNEL_FILE_MASK
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
        Push-Location $repoRoot
        try {
            $positive = Invoke-KernelFileMaskTest "0x1480"
            $positiveTail = (($positive.Output -split "`r?`n") | Select-Object -Last 8) -join "; "
            if ($positive.ExitCode -eq 0) {
                Add-Result "#708 0x1480 emits only Kernel-File IDs 12, 26, 30" "PASS" "real ETW session; create/write/rename/delete observed; $positiveTail"
            } else {
                Add-Result "#708 0x1480 emits only Kernel-File IDs 12, 26, 30" "FAIL" "cargo test exit $($positive.ExitCode); $positiveTail"
            }

            $negative = Invoke-KernelFileMaskTest "0x1E80"
            $negativeTail = (($negative.Output -split "`r?`n") | Select-Object -Last 8) -join "; "
            if ($negative.ExitCode -ne 0 -and $negative.Output -match "mask validation failed: unexpected Kernel-File IDs") {
                Add-Result "#708 bad mask 0x1E80 is rejected by the same assertion" "PASS" "the test saw Kernel-File IDs outside 12, 26, 30 under the wider mask, as expected; $negativeTail"
            } else {
                Add-Result "#708 bad mask 0x1E80 is rejected by the same assertion" "FAIL" "exit $($negative.ExitCode), expected the failure 'unexpected Kernel-File IDs' (a 'missing' failure or a session problem does not prove the bad mask lets extra IDs through); $negativeTail"
            }
        } finally {
            Pop-Location
            if ($hadKernelFileMask) {
                $env:SYNTHAEA_KERNEL_FILE_MASK = $previousKernelFileMask
            } else {
                Remove-Item Env:SYNTHAEA_KERNEL_FILE_MASK -ErrorAction SilentlyContinue
            }
        }
    }
}
finally {
    Write-Section "Cleanup"
    Stop-LabAgent $Current
    if ($KernelFileMaskNeedsCleanup -and $KernelFileMaskSession) {
        Invoke-NativeCleanup "ETW session $KernelFileMaskSession" logman.exe @("stop", $KernelFileMaskSession, "-ets")
    }
    Stop-EtsSessions $ProbePrefix
    Stop-EtsSessions $CapturePrefix
    Stop-EtsSessions $AgentPrefix
    foreach ($dir in $LabDirs) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    $Results | Format-Table -AutoSize -Wrap | Out-String -Width 400 | Set-Content -LiteralPath (Join-Path $OutDir "summary.txt") -Encoding UTF8
    Write-Host ""
    Write-Host "Summary: $(Join-Path $OutDir 'summary.txt')"
    $failed = @($Results | Where-Object { $_.Verdict -eq "FAIL" }).Count
    if ($failed -gt 0) { Write-Host "$failed check(s) FAILED" -ForegroundColor Red } else { Write-Host "no failed check" -ForegroundColor Green }
}
