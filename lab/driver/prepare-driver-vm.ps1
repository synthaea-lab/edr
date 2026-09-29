<#
.SYNOPSIS
    One-time guest setup of the driver test VM (run INSIDE the VM, elevated).

.DESCRIPTION
    Turns a fresh Windows 11 guest into a place a test-signed minifilter can
    load, and a crash can be read:
      1. checks it runs in a VirtualBox or VMware guest (never a host, ADR-0012) and
         that Secure Boot is off (test-signing is refused under it);
      2. trusts the developer's test certificate (Root + TrustedPublisher);
      3. `bcdedit /set testsigning on`, kernel debugging on COM1, which
         new-driver-vm.ps1 exposes on the host as \\.\pipe\<vm>-kd (on
         VMware, add a serial port on a named pipe in the VM settings);
      4. shows DbgPrint output (Debug Print Filter), keeps a kernel memory
         dump and stops on a bugcheck instead of rebooting past it;
      5. optionally enables Driver Verifier for the driver (ADR-0012
         guardrail 3), once its file name is known.
    A reboot applies it; then take the clean snapshot from the host.

.PARAMETER VerifierDriver
    The driver's file name (e.g. synthaea.sys) to put under Driver Verifier's
    standard checks. Re-run with it once the name is settled.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File \\VBoxSvr\synthaea\lab\driver\prepare-driver-vm.ps1
    (VMware: from the repo's shared folder, e.g. "\\vmware-host\Shared Folders\edr-new\lab\driver\...".
    The certificate and package paths follow the script's own location.)
#>
[CmdletBinding()]
param(
    [string]$CertPath,
    [string]$VerifierDriver
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common-driver.ps1")

Assert-Admin
Assert-InTestVm

$secureBoot = $false
try { $secureBoot = Confirm-SecureBootUEFI } catch { $secureBoot = $false }
if ($secureBoot) {
    throw ("Secure Boot is on. Power the VM off, then on the host: VirtualBox: VBoxManage modifynvram <vm> secureboot --disable; " +
        "VMware: VM Settings > Options > Advanced > untick 'Enable secure boot'.")
}
Write-Host "[ok] Secure Boot off"

if (-not $CertPath) { $CertPath = Join-Path (Get-DriverOutDir) "cert\synthaea-driver-test.cer" }
if (-not (Test-Path $CertPath)) { throw "no certificate at $CertPath; run new-test-cert.ps1 on the host first" }
$CertPath = (Resolve-Path $CertPath).Path
$thumbprint = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 $CertPath).Thumbprint
# Import-Certificate into LocalMachine\TrustedPublisher failed with
# E_ACCESSDENIED from an elevated shell on a VMware guest while Root worked
# (#516 review); certutil adds to both. The thumbprint check catches a store
# that exits 0 without holding the certificate.
foreach ($store in @("Root", "TrustedPublisher")) {
    Invoke-Native certutil.exe @("-addstore", "-f", $store, $CertPath)
    if (-not (Test-Path "Cert:\LocalMachine\$store\$thumbprint")) {
        throw "certutil -addstore $store exited 0 but $thumbprint is not in LocalMachine\$store"
    }
}
Write-Host "[ok] test certificate trusted (Root, TrustedPublisher)"

Invoke-Native bcdedit.exe @("/set", "testsigning", "on")
Invoke-Native bcdedit.exe @("/debug", "on")
Invoke-Native bcdedit.exe @("/dbgsettings", "serial", "debugport:1", "baudrate:115200")
Write-Host "[ok] test-signing on, kernel debugger on COM1 (115200)"

$filter = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter"
New-Item -Path $filter -Force | Out-Null
# One mask per component: DEFAULT covers plain DbgPrint, IHVDRIVER the
# driver's DbgPrintEx(DPFLTR_IHVDRIVER_ID, ...) traces (#508).
foreach ($component in @("DEFAULT", "IHVDRIVER")) {
    New-ItemProperty -Path $filter -Name $component -PropertyType DWord -Value 0xF -Force | Out-Null
}
$crash = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
Set-ItemProperty -Path $crash -Name "CrashDumpEnabled" -Value 2   # kernel memory dump
Set-ItemProperty -Path $crash -Name "AutoReboot" -Value 0
Write-Host "[ok] DbgPrint visible, kernel dump kept in %SystemRoot%\MEMORY.DMP, no auto-reboot on bugcheck"

if ($VerifierDriver) {
    Invoke-Native verifier.exe @("/standard", "/driver", $VerifierDriver)
    Write-Host "[ok] Driver Verifier (standard) on $VerifierDriver"
}

Write-Host ""
Write-Host "Reboot the guest now (Restart-Computer). Then, on the host:"
Write-Host "  .\lab\driver\snapshot-driver-vm.ps1 -Take clean"
