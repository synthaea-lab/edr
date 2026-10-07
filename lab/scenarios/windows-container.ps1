<#
.SYNOPSIS
    Process-isolated Windows container attribution scenario (#371).

.DESCRIPTION
    Runs a process-isolated container, starts a long-lived process in it and a
    short-lived one with `docker exec`, and one short-lived process on the host.
    The ETW sensor must stamp the container's processes with the container id
    (EventMeta::container, the Host Compute Service id that Docker shows), and
    leave the host process without one.

    Alongside the checks it prints what the attribution rests on, so a FAIL can
    be told apart from a wrong assumption:
      - the ServerSiloId of each process `docker top` lists (the query the
        sensor makes at ProcessStart);
      - `hcsdiag list`, the Host Compute Service's view of the container;
      - the Kernel-Process server-silo records (EIDs 22-26) of the run, traced
        with logman: the sensor forgets a silo on their "Job ID", which must be
        the ServerSiloId above.

    Needs a host with the Containers feature and Docker in Windows-containers
    mode (Windows Server 2025, or Windows 11 22H2+ Pro/Enterprise), and an image
    whose build matches the host's (process isolation requires it).

.NOTES
    Self-checking run (elevated, no other agent running):
        cargo build --release -p agent
        powershell -ExecutionPolicy Bypass -File lab\scenarios\windows-container.ps1 -AgentExe target\release\agent.exe

    Expected:
        - exec events from inside the container carry container.id = the
          container's full id (64 hex), including hostname.exe run by
          `docker exec` (a process that exits at once: it takes its parent's silo)
        - the host's hostname.exe exec has no container
        - the Kernel-Process silo records name the ServerSiloId docker top's
          processes run in

.LINK
    https://github.com/synthaea-lab/edr/issues/371
#>
param(
    [string]$Image = "mcr.microsoft.com/windows/nanoserver:ltsc2025",
    [string]$AgentExe = "",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

$Name = "synthaea371"
$TraceName = "synthaea371-silo"

Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class SynthaeaSilo {
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, out uint info, int len, out int retLen);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    // 109 = ProcessMembershipInformation (ntddk.h), as the sensor queries it.
    public static string ServerSiloId(int pid) {
        IntPtr h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return "open failed";
        uint silo; int len; int status = NtQueryInformationProcess(h, 109, out silo, 4, out len);
        CloseHandle(h);
        return status == 0 ? silo.ToString() : String.Format("status 0x{0:X8}", status);
    }
}
'@

# -- Agent harness (-AgentExe), as in bits-job.ps1 ----------------------------

function Start-ScenarioAgent([string]$Dir) {
    if (-not (Test-Path $AgentExe)) { throw "agent.exe not found at $AgentExe (cargo build --release -p agent)" }
    if (Get-Process -Name "agent" -ErrorAction SilentlyContinue) {
        throw "An agent.exe is already running; stop it first (this run starts its own)."
    }
    $exe = (Resolve-Path $AgentExe).Path
    $config = Join-Path $Dir "agent.toml"
    @"
schema_version = 1

[server]
control_plane_url = "https://cp.lab.invalid"
mtls_cert = '$Dir\certs\client.crt'
mtls_key = '$Dir\certs\client.key'
mtls_passphrase = "envvar:SYNTHAEA_MTLS_PASSPHRASE"
offline_fallback = true

[log]
dir = '$Dir\logs'
level = "info"
max_mb = 64

[storage]
state_dir = '$Dir\state'
spool_max_mb = 64

[ipc]
endpoint = '\\.\pipe\synthaea-lab-container'

[resources]
worker_threads = 0
max_reconnect_backoff_ms = 60000
"@ | Set-Content -LiteralPath $config -Encoding Ascii
    $events = Join-Path $Dir "events.jsonl"
    $alerts = Join-Path $Dir "alerts.ndjson"
    $agentArgs = @("--config", "`"$config`"", "run", "--alerts", "`"$alerts`"", "--events", "`"$events`"")
    $proc = Start-Process -FilePath $exe -ArgumentList $agentArgs -WorkingDirectory $Dir `
        -RedirectStandardOutput "$Dir\stdout.log" -RedirectStandardError "$Dir\stderr.log" `
        -WindowStyle Hidden -PassThru
    Write-Host "agent started (pid $($proc.Id)), output in $Dir"
    $deadline = (Get-Date).AddSeconds(30)
    while (-not ((Test-Path $events) -and (Get-Item $events).Length -gt 0)) {
        if ($proc.HasExited) { throw "the agent exited at startup; see $Dir\stderr.log" }
        if ((Get-Date) -gt $deadline) { throw "the agent produced no events in 30s; see $Dir\stderr.log" }
        Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Seconds 2
    if ((Get-Content -LiteralPath "$Dir\stderr.log" -Raw -ErrorAction SilentlyContinue) -match "ETW sensor failed") {
        Stop-Process -Id $proc.Id -Force
        throw "the agent's ETW sensor failed to start; see $Dir\stderr.log"
    }
    [pscustomobject]@{ Process = $proc; Events = $events }
}

function Stop-ScenarioAgent($Agent) {
    if ($Agent -and -not $Agent.Process.HasExited) {
        Stop-Process -Id $Agent.Process.Id -Force
        $Agent.Process.WaitForExit(10000) | Out-Null
    }
}

# -- Scenario ------------------------------------------------------------------

function Assert-Prerequisites {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "needs an elevated PowerShell (the agent's ETW session, logman, hcsdiag)"
    }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "docker not found on PATH" }
    $osType = (docker info --format "{{.OSType}}" 2>$null)
    if ($osType -ne "windows") { throw "docker is not in Windows-containers mode (OSType=$osType)" }
    Write-Host "pulling $Image (once, before the trace starts)"
    Invoke-Native docker @("pull", "-q", $Image)
}

function Invoke-ContainerScenario {
    docker rm -f $Name 2>$null | Out-Null
    Write-Host "docker run --isolation=process $Image (ping -t, kept running)"
    $id = (docker run -d --isolation=process --name $Name $Image cmd /c "ping -t 127.0.0.1").Trim()
    if ($LASTEXITCODE -ne 0 -or $id -notmatch '^[0-9a-f]{64}$') { throw "docker run failed: $id" }
    Write-Host "container id $id"
    # The first processes of a container start before the Host Compute Service
    # lists them; the sensor's lookup retries, and these runs come after.
    Start-Sleep -Seconds 6
    Write-Host "docker exec $Name hostname.exe (exits at once)"
    Invoke-Native docker @("exec", $Name, "hostname.exe")
    Write-Host "hostname.exe on the host"
    $hostProc = Start-Process -FilePath "$env:SystemRoot\System32\HOSTNAME.EXE" -WindowStyle Hidden -PassThru -Wait
    [pscustomobject]@{ Id = $id; HostPid = $hostProc.Id }
}

function Show-SiloDiagnostics([string]$Dir) {
    Write-Host ""
    Write-Host "docker top $Name, with each process's ServerSiloId:"
    $siloIds = @()
    foreach ($line in (docker top $Name 2>$null | Select-Object -Skip 1)) {
        $fields = $line -split '\s+' | Where-Object { $_ }
        $hostPid = $fields | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
        if (-not $hostPid) { continue }
        $silo = [SynthaeaSilo]::ServerSiloId([int]$hostPid)
        if ($silo -match '^\d+$' -and $silo -ne "0") { $siloIds += $silo }
        Write-Host ("  {0,-24} pid {1,-7} silo {2}" -f $fields[0], $hostPid, $silo)
    }
    if (Get-Command hcsdiag -ErrorAction SilentlyContinue) {
        Write-Host ""
        Write-Host "hcsdiag list:"
        hcsdiag list | ForEach-Object { Write-Host "  $_" }
    }
    @($siloIds | Select-Object -Unique)
}

function Get-SiloTraceRecords([string]$Dir) {
    $xml = Join-Path $Dir "silo.xml"
    Invoke-Native tracerpt @("$Dir\silo.etl", "-o", $xml, "-of", "XML", "-y")
    $records = @()
    foreach ($e in ([xml](Get-Content -LiteralPath $xml -Raw)).Events.Event) {
        $eid = [int]$e.System.EventID
        if ($eid -lt 22 -or $eid -gt 26) { continue }
        $data = @{}
        foreach ($d in $e.EventData.Data) { $data[$d.Name] = $d.'#text' }
        $records += [pscustomobject]@{ Eid = $eid; JobId = $data["Job ID"]; ContainerId = $data["Container ID"] }
    }
    Write-Host ""
    Write-Host "Kernel-Process server-silo records (EIDs 22-26): $($records.Count)"
    $records | ForEach-Object { Write-Host ("  EID {0} Job ID {1} Container ID {2}" -f $_.Eid, $_.JobId, $_.ContainerId) }
    $records
}

function Test-Scenario($Agent, $Run, $SiloIds, $SiloRecords) {
    $execs = @(Get-Content -LiteralPath $Agent.Events | Where-Object { $_.StartsWith('{"type":"exec"') } |
        ForEach-Object { $_ | ConvertFrom-Json })
    $inContainer = @($execs | Where-Object { $_.meta.container.id -eq $Run.Id })
    $provisional = @($execs | Where-Object { "$($_.meta.container.id)".StartsWith("silo:") })
    $results = @()
    $results += [pscustomobject]@{
        Check = "exec events from the container carry its id"
        Pass = $inContainer.Count -gt 0
        Detail = "$($inContainer.Count) event(s): $(($inContainer | ForEach-Object { $_.meta.comm } | Select-Object -Unique) -join ', ')"
    }
    $execd = @($inContainer | Where-Object { $_.meta.comm -ieq "hostname.exe" })
    $results += [pscustomobject]@{
        Check = "docker exec'd hostname.exe carries the container id"
        Pass = $execd.Count -ge 1
        Detail = "$($execd.Count) event(s)"
    }
    $hostExec = @($execs | Where-Object { $_.meta.pid -eq $Run.HostPid })
    $results += [pscustomobject]@{
        Check = "the host's hostname.exe has no container"
        Pass = ($hostExec.Count -ge 1) -and (@($hostExec | Where-Object { $_.meta.container }).Count -eq 0)
        Detail = "$($hostExec.Count) event(s) for pid $($Run.HostPid)"
    }
    $jobIds = @($SiloRecords | ForEach-Object { $_.JobId } | Select-Object -Unique)
    $results += [pscustomobject]@{
        Check = "the silo records' Job ID is the ServerSiloId the processes run in"
        Pass = ($SiloIds.Count -eq 1) -and ($jobIds -contains $SiloIds[0])
        Detail = "ServerSiloId [$($SiloIds -join ',')], Job IDs [$($jobIds -join ',')]"
    }
    Write-Host ""
    Write-Host ("info: {0} exec event(s) carried a provisional silo:<n> id: {1}" -f $provisional.Count,
        (($provisional | ForEach-Object { "$($_.meta.comm)=$($_.meta.container.id)" } | Select-Object -Unique) -join ', '))
    foreach ($r in $results) {
        $verdict = if ($r.Pass) { "PASS" } else { "FAIL" }
        Write-Host ("{0}  {1}: {2}" -f $verdict, $r.Check, $r.Detail) -ForegroundColor $(if ($r.Pass) { "Green" } else { "Red" })
    }
    @($results | Where-Object { -not $_.Pass }).Count -eq 0
}

Assert-Prerequisites
$dir = $OutDir
if (-not $dir) { $dir = Join-Path $PSScriptRoot ("..\..\target\lab-validation\container-" + (Get-Date -Format "yyyyMMdd-HHmmss")) }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$dir = (Resolve-Path $dir).Path

$agent = $null
$run = $null
$siloIds = @()
logman stop $TraceName -ets 2>$null | Out-Null
Invoke-Native logman @("start", $TraceName, "-p", "Microsoft-Windows-Kernel-Process", "0x4000", "-ets", "-o", "$dir\silo.etl")
try {
    if ($AgentExe) { $agent = Start-ScenarioAgent $dir }
    $run = Invoke-ContainerScenario
    $siloIds = Show-SiloDiagnostics $dir
    if ($agent) { Start-Sleep -Seconds 8 }
}
finally {
    Stop-ScenarioAgent $agent
    Invoke-NativeCleanup "container $Name" docker @("rm", "-f", $Name)
    Invoke-NativeCleanup "trace session $TraceName" logman @("stop", $TraceName, "-ets")
}
$siloRecords = Get-SiloTraceRecords $dir

if ($agent) {
    if (-not (Test-Scenario $agent $run $siloIds $siloRecords)) {
        Write-Host "see $dir (events.jsonl, stderr.log, silo.xml)"
        exit 1
    }
}
else {
    Write-Host ""
    Write-Host "Done. Expected from the agent: exec events of the container with container.id $($run.Id),"
    Write-Host "and none on the host's hostname.exe (pid $($run.HostPid))."
}
