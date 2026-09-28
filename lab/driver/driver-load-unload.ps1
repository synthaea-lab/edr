<#
.SYNOPSIS
    Milestone 1 check, replayed at the demo: install the signed minifilter,
    load it, see it attached, unload it (run INSIDE the VM, elevated).

.DESCRIPTION
    ADR-0012's first milestone: a minifilter that registers, loads and
    unloads cleanly on a test-signed VM. Each step is checked, not just run:
      1. preconditions: VirtualBox or VMware guest, test-signing on, the package's
         signatures valid (so the test certificate is trusted here);
      2. copies the package locally and installs it from its INF;
      3. `fltmc load`, then the filter must be listed by `fltmc filters`;
      4. waits -HoldSeconds (time to show `fltmc instances` at the demo);
      5. `fltmc unload`, then the filter must be gone;
      6. prints any FilterManager event logged during the run.
    Take a snapshot from the host first (snapshot-driver-vm.ps1 -Take
    pre-load): a bug here bluescreens the VM.

.PARAMETER PackageDir
    The signed package (sign-driver.ps1). Default: target\driver\package
    next to this script's repository, i.e. the host's through the VM's
    shared folder (\\VBoxSvr\synthaea, or VMware's \\vmware-host\Shared Folders\...).

.PARAMETER FilterName
    The filter's service name. Default: read from the INF's AddService line.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File \\VBoxSvr\synthaea\lab\driver\driver-load-unload.ps1
#>
[CmdletBinding()]
param(
    [string]$PackageDir,
    [string]$FilterName,
    [int]$HoldSeconds = 5,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common-driver.ps1")

function Get-InfServiceName([string]$InfPath) {
    $lines = Get-Content -LiteralPath $InfPath
    $service = $lines | Where-Object { $_ -match '^\s*AddService\s*=\s*([^,\s]+)' } |
        ForEach-Object { $Matches[1] } | Select-Object -First 1
    if (-not $service) { throw "no AddService line in $InfPath; pass -FilterName" }
    if ($service -match '^%(.+)%$') {
        $key = $Matches[1]
        $value = $lines | Where-Object { $_ -match ('^\s*' + [regex]::Escape($key) + '\s*=\s*"?([^"]+)"?\s*$') } |
            ForEach-Object { $Matches[1].Trim() } | Select-Object -First 1
        if (-not $value) { throw "AddService uses %$key% but [Strings] has no $key; pass -FilterName" }
        $service = $value
    }
    $service.Trim('"')
}

function Invoke-Fltmc([string[]]$FltArgs) {
    # PowerShell 5.1 turns redirected native stderr into a terminating error
    # under "Stop"; the exit code is the check here.
    $ErrorActionPreference = "Continue"
    $out = & fltmc.exe @FltArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "fltmc $($FltArgs -join ' ') failed ($LASTEXITCODE): $($out -join ' ')" }
    $out
}

function Test-FilterLoaded([string]$Name) {
    # First column of `fltmc filters` is the filter name; headers are localized.
    [bool](Invoke-Fltmc @("filters") | Where-Object { ("$_".Trim() -split '\s+')[0] -eq $Name })
}

function Write-Step([string]$Text) { Write-Host "[..] $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text) { Write-Host "[ok] $Text" -ForegroundColor Green }

Assert-Admin
Assert-InTestVm
if (-not (Test-TestSigningOn)) { throw "test-signing is off; run prepare-driver-vm.ps1 and reboot" }

if (-not $PackageDir) { $PackageDir = Join-Path (Get-DriverOutDir) "package" }
$inf = @(Get-ChildItem -LiteralPath $PackageDir -Filter *.inf)
$sys = @(Get-ChildItem -LiteralPath $PackageDir -Filter *.sys)
if ($inf.Count -ne 1 -or $sys.Count -ne 1) { throw "expected one .inf and one .sys in $PackageDir; run sign-driver.ps1 on the host" }
foreach ($file in @($sys[0]) + @(Get-ChildItem -LiteralPath $PackageDir -Filter *.cat)) {
    $status = (Get-AuthenticodeSignature -LiteralPath $file.FullName).Status
    if ($status -ne "Valid") { throw "$($file.Name) signature is $status here; is the test certificate trusted (prepare-driver-vm.ps1)?" }
}
if (-not $FilterName) { $FilterName = Get-InfServiceName $inf[0].FullName }

$runRoot = "C:\synthaea-driver"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$local = Join-Path $runRoot $stamp
New-Item -ItemType Directory -Force -Path $local | Out-Null
Start-Transcript -Path (Join-Path $runRoot "cycle-$stamp.log") | Out-Null
$started = Get-Date
try {
    Copy-Item -Path (Join-Path $PackageDir "*") -Destination $local
    $localInf = Join-Path $local $inf[0].Name
    Write-Ok "package $($sys[0].Name) copied to $local, filter '$FilterName'"

    if (Test-FilterLoaded $FilterName) {
        Write-Step "left loaded by a previous run, unloading first"
        Invoke-Fltmc @("unload", $FilterName) | Out-Null
    }

    Write-Step "installing from $($inf[0].Name)"
    $section = "DefaultInstall"
    if ((Get-Content -LiteralPath $localInf) -match '^\s*\[DefaultInstall\.NTamd64\]') { $section = "DefaultInstall.NTamd64" }
    $installedBy = $null
    # Build 25952+ INFs (the nullFilter template, #508) install into the driver
    # store (%13%) through pnputil, which also picks the OS-decorated section
    # and checks the catalog. The legacy InstallHinfSection path stays as the
    # fallback for an INF without a catalog or without that section.
    if (@(Get-ChildItem -LiteralPath $local -Filter *.cat).Count -eq 1) {
        $ErrorActionPreference = "Continue"
        $pnp = & pnputil.exe /add-driver $localInf /install 2>&1
        $pnpExit = $LASTEXITCODE
        $ErrorActionPreference = "Stop"
        if (Get-Service -Name $FilterName -ErrorAction SilentlyContinue) {
            $installedBy = "pnputil"
        } else {
            Write-Host "     pnputil did not create the service (exit $pnpExit): $($pnp -join ' ')"
        }
    }
    if (-not $installedBy) {
        # InstallHinfSection reports nothing through its exit code; the service is the proof.
        Start-Process -FilePath rundll32.exe -ArgumentList @("setupapi.dll,InstallHinfSection", $section, "132", "`"$localInf`"") -Wait
        if (Get-Service -Name $FilterName -ErrorAction SilentlyContinue) { $installedBy = "InstallHinfSection [$section]" }
    }
    if (-not $installedBy) { throw "neither pnputil nor InstallHinfSection [$section] created a '$FilterName' service" }
    Write-Ok "service $FilterName installed ($installedBy)"

    Write-Step "fltmc load $FilterName"
    Invoke-Fltmc @("load", $FilterName) | Out-Null
    if (-not (Test-FilterLoaded $FilterName)) { throw "fltmc load succeeded but $FilterName is not in fltmc filters" }
    Write-Ok "$FilterName loaded"
    Invoke-Fltmc @("filters") | Write-Host
    Invoke-Fltmc @("instances", "-f", $FilterName) | Write-Host

    Start-Sleep -Seconds $HoldSeconds

    Write-Step "fltmc unload $FilterName"
    Invoke-Fltmc @("unload", $FilterName) | Out-Null
    if (Test-FilterLoaded $FilterName) { throw "fltmc unload succeeded but $FilterName is still listed" }
    Write-Ok "$FilterName unloaded"

    if ($Uninstall) {
        $uninstallSection = $section -replace "DefaultInstall", "DefaultUninstall"
        Start-Process -FilePath rundll32.exe -ArgumentList @("setupapi.dll,InstallHinfSection", $uninstallSection, "132", "`"$localInf`"") -Wait
        Write-Ok "uninstalled ([$uninstallSection])"
    }

    Write-Host ""
    Write-Host "MILESTONE 1 PASS: $FilterName installed, loaded, attached, unloaded" -ForegroundColor Green
}
finally {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Microsoft-Windows-FilterManager"; StartTime = $started } -ErrorAction SilentlyContinue)
    if ($events.Count -gt 0) {
        Write-Host "FilterManager events during the run:"
        $events | ForEach-Object { Write-Host ("  {0} id={1} {2}" -f $_.TimeCreated.ToString("HH:mm:ss"), $_.Id, $_.Message) }
    }
    Stop-Transcript | Out-Null
}
