<#
.SYNOPSIS
    BITS download-then-exec scenario for T1197 (#284).

.DESCRIPTION
    Asserts the Bits-Client ETW path end to end: `bitsadmin /transfer` fetches
    a copy of whoami.exe from a local HTTP listener into %TEMP%, then runs it.
    The sensor reports the job (BitsJob file_added, then completed) and the
    T1197 download->exec join fires on the exec. BITS does the download from
    its own service, so without the Bits-Client provider nothing ties the file
    to bitsadmin.exe.

    The listener answers HEAD and ranged GETs: BITS sizes the file with a HEAD
    and fetches it with Range requests. Benign by construction: the "payload"
    is whoami.exe, and the only network traffic is to localhost.

    With -MicrosoftJob (needs internet), a second job fetches
    http://www.msftconnecttest.com/connecttest.txt: a Microsoft update host,
    so the sensor must drop it, with no bits_job event for that job.

.NOTES
    Usage:
        1) terminal A (as Administrator):
             target\release\agent.exe run --events events.jsonl
        2) terminal B (any user):
             powershell -ExecutionPolicy Bypass -File lab\scenarios\bits-job.ps1
        3) expected:
             - events.jsonl: two "bits_job" events for job "synthaea284",
               state file_added then completed, comm bitsadmin.exe,
               url http://localhost:<port>/payload284.exe
             - one alert:
               T1197 -- pid=<p> comm=payload284.exe executes ...\payload284.exe,
               <n>s earlier by BITS job "synthaea284" of pid=<b> comm=bitsadmin.exe
             - with -MicrosoftJob: no bits_job event naming synthaea284ms

    Without the agent, the same records can be read from the
    Microsoft-Windows-Bits-Client/Operational log: the script prints the ones
    for its jobs (16403 file added, 4 completed) as a self-check.

.LINK
    ATT&CK T1197 -- https://attack.mitre.org/techniques/T1197/
#>
[CmdletBinding()]
param(
    [int]$Port = 18284,
    [switch]$MicrosoftJob
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

$JobName = "synthaea284"
$Source = "$env:SystemRoot\System32\whoami.exe"
$Target = Join-Path $env:TEMP "payload284.exe"
$Url = "http://localhost:$Port/payload284.exe"

# The listener serves from its own runspace: bitsadmin /transfer blocks until
# the job is done, and BITS makes several requests (HEAD, then ranged GETs).
# It is created here so the cleanup can stop it: stopping the runspace alone
# does not interrupt a blocked GetContext().
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
$listenerScript = {
    param($Listener, $Bytes)
    try {
        while ($Listener.IsListening) {
            $context = $Listener.GetContext()
            $response = $context.Response
            $response.Headers.Add("Accept-Ranges", "bytes")
            $response.ContentType = "application/octet-stream"
            $first = 0
            $last = $Bytes.Length - 1
            $range = $context.Request.Headers["Range"]
            if ($range -match "^bytes=(\d+)-(\d*)$") {
                $first = [int64]$Matches[1]
                if ($Matches[2]) { $last = [Math]::Min([int64]$Matches[2], $last) }
                $response.StatusCode = 206
                $response.Headers.Add("Content-Range", "bytes $first-$last/$($Bytes.Length)")
            }
            $count = $last - $first + 1
            $response.ContentLength64 = $count
            if ($context.Request.HttpMethod -ne "HEAD") {
                $response.OutputStream.Write($Bytes, $first, $count)
            }
            $response.Close()
        }
    }
    catch [System.Net.HttpListenerException] {
        # Stop() from the cleanup: the blocked GetContext() returns here.
    }
}

$server = [PowerShell]::Create()
[void]$server.AddScript($listenerScript).AddArgument($listener).AddArgument([IO.File]::ReadAllBytes($Source))
$handle = $server.BeginInvoke()
$started = Get-Date
try {
    Start-Sleep -Seconds 1
    if ($handle.IsCompleted) {
        $server.EndInvoke($handle)
        throw "the HTTP listener runspace exited at once"
    }
    Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue

    Write-Host "bitsadmin /transfer $JobName $Url -> $Target"
    Invoke-Native bitsadmin.exe @("/transfer", $JobName, "/download", "/priority", "foreground", $Url, $Target)
    if (-not (Test-Path -LiteralPath $Target)) { throw "bitsadmin reported success but $Target is missing" }

    Write-Host "running $Target"
    & $Target | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$Target failed with exit code $LASTEXITCODE" }

    if ($MicrosoftJob) {
        $msTarget = Join-Path $env:TEMP "connecttest284.txt"
        Write-Host "bitsadmin /transfer ${JobName}ms (Microsoft host, must be filtered)"
        Invoke-Native bitsadmin.exe @("/transfer", "${JobName}ms", "/download", "/priority", "foreground",
            "http://www.msftconnecttest.com/connecttest.txt", $msTarget)
        Remove-Item -LiteralPath $msTarget -Force -ErrorAction SilentlyContinue
    }
}
finally {
    $listener.Stop()
    $listener.Close()
    [void]$handle.AsyncWaitHandle.WaitOne(5000)
    $server.Dispose()
    Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue
}

# Self-check without the agent: what the Bits-Client log recorded for our jobs.
Start-Sleep -Seconds 1
$records = @(Get-WinEvent -LogName "Microsoft-Windows-Bits-Client/Operational" -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -ge $started -and $_.Id -in 4, 5, 16403, 61 } |
    Where-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.'#text' -like "$JobName*" } })
Write-Host ""
Write-Host "Bits-Client records for ${JobName}*: $($records.Count)"
foreach ($record in ($records | Sort-Object TimeCreated)) {
    $data = @{}
    ([xml]$record.ToXml()).Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
    Write-Host ("  EID {0,-5} {1,-14} processId={2} {3} {4}" -f $record.Id, $data["jobTitle"], $data["processId"], $data["RemoteName"], $data["LocalName"])
}
if (@($records | Where-Object { $_.Id -eq 16403 }).Count -eq 0) {
    Write-Warning "no 16403 (file added) record: the sensor has nothing to report either"
}
Write-Host ""
Write-Host "Done. Expected from the agent: bits_job file_added + completed for $JobName,"
Write-Host "then one T1197 alert for payload284.exe."
