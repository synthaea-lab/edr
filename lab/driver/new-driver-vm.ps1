<#
.SYNOPSIS
    Creates the VirtualBox VM a developer loads the minifilter into (ADR-0012).

.DESCRIPTION
    One test-signing VM per developer, separate from the demo VM, never the
    host (ADR-0012 Acceptance). The VM this creates:
      - Windows 11 x64, EFI, TPM 2.0 (what Windows 11 setup requires);
      - Secure Boot OFF: the UEFI variable store is initialized without any
        key enrolled, which is what test-signing needs. prepare-driver-vm.ps1
        re-checks it from inside the guest;
      - COM1 exposed on the named pipe \\.\pipe\<Name>-kd for WinDbg kernel
        debugging (prepare-driver-vm.ps1 points the guest debugger at COM1);
      - lab\ and target\driver shared read-only as \\VBoxSvr\synthaea-lab
        and \\VBoxSvr\synthaea-driver, so the guest reads the scripts, the
        certificate and the signed package without copying them, and sees
        nothing else of the checkout;
      - an unattended install with the Guest Additions, unless -Manual.

    VirtualBox rather than Hyper-V: the team's hosts include Windows 11 Home,
    which has no Hyper-V (2026-09-28).

.PARAMETER IsoPath
    A Windows 11 x64 ISO. Its images are listed by
    `VBoxManage unattended detect --iso=<path>`.

.PARAMETER BaseFolder
    Where the VM's folder is created. Default: VirtualBox's default machine
    folder. The disk grows to -DiskGB plus snapshots; pick a roomy drive.

.PARAMETER ImageIndex
    The edition to install. 6 is "Professionnel" / "Pro" on the 25H2
    consumer ISO; check with `unattended detect` for another ISO.

.PARAMETER Manual
    Only create the VM and attach the ISO; install Windows by hand.

.EXAMPLE
    .\new-driver-vm.ps1 -IsoPath $env:USERPROFILE\Downloads\Win11_25H2_French_x64_v2.iso -BaseFolder E:\VMs
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$IsoPath,
    [string]$Name = "synthaea-driver-$($env:USERNAME.ToLower())",
    [string]$BaseFolder,
    [int]$MemoryMB = 8192,
    [int]$Cpus = 4,
    [int]$DiskGB = 80,
    [int]$ImageIndex = 6,
    [string]$Locale = "fr_FR",
    [string]$Country = "FR",
    [string]$User = "lab",
    [switch]$Manual,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common-driver.ps1")

$vbm = Get-VBoxManage
$IsoPath = (Resolve-Path $IsoPath).Path
$labDir = Join-Path (Get-RepoRoot) "lab"
# Shared before new-test-cert.ps1 or sign-driver.ps1 may have run.
$driverOut = Get-DriverOutDir
New-Item -ItemType Directory -Force -Path $driverOut | Out-Null

$existing = & $vbm list vms
if ($existing -match ('^"' + [regex]::Escape($Name) + '"')) {
    throw "A VM named $Name already exists; remove it (VBoxManage unregistervm $Name --delete) or pass -Name"
}
if (-not $Manual) {
    $password = Read-Host "Password for the guest account '$User' (also the Administrator password)" -AsSecureString
}

Write-Host "Creating $Name ..."
$create = @("createvm", "--name=$Name", "--ostype=Windows11_64", "--register")
if ($BaseFolder) {
    New-Item -ItemType Directory -Force -Path $BaseFolder | Out-Null
    $create += "--basefolder=$BaseFolder"
}
Invoke-Native $vbm $create

try {
    Invoke-Native $vbm @("modifyvm", $Name,
        "--memory=$MemoryMB", "--cpus=$Cpus", "--firmware=efi", "--tpm-type=2.0",
        "--graphicscontroller=vboxsvga", "--vram=128", "--audio-enabled=off", "--usb-xhci=on",
        "--nic1=nat", "--nic-type1=82540EM",
        "--uart1", "0x3F8", "4", "--uart-mode1", "server", "\\.\pipe\$Name-kd")
    # No key enrolled = Secure Boot off; Windows 11 setup only needs it to be capable.
    Invoke-Native $vbm @("modifynvram", $Name, "inituefivarstore")

    $vmDir = Split-Path -Parent ((& $vbm showvminfo $Name --machinereadable |
        Where-Object { $_ -like "CfgFile=*" }) -replace '^CfgFile="(.*)"$', '$1')
    $disk = Join-Path $vmDir "$Name.vdi"
    Invoke-Native $vbm @("createmedium", "disk", "--filename=$disk", "--size=$($DiskGB * 1024)", "--format=VDI")
    Invoke-Native $vbm @("storagectl", $Name, "--name=SATA", "--add=sata", "--controller=IntelAhci", "--portcount=4", "--bootable=on")
    Invoke-Native $vbm @("storageattach", $Name, "--storagectl=SATA", "--port=0", "--device=0", "--type=hdd", "--medium=$disk")
    Invoke-Native $vbm @("sharedfolder", "add", $Name, "--name=$LabShareName", "--hostpath=$labDir", "--readonly", "--automount")
    Invoke-Native $vbm @("sharedfolder", "add", $Name, "--name=$DriverShareName", "--hostpath=$driverOut", "--readonly", "--automount")

    if ($Manual) {
        Invoke-Native $vbm @("storageattach", $Name, "--storagectl=SATA", "--port=1", "--device=0", "--type=dvddrive", "--medium=$IsoPath")
        if (-not $NoStart) {
            Invoke-Native $vbm @("startvm", $Name, "--type=gui")
            Write-Host "VM started on the installer. Install Windows, then the Guest Additions (Devices menu)."
        }
    } else {
        $passwordFile = Join-Path $env:TEMP ("synthaea-vm-" + [guid]::NewGuid() + ".txt")
        try {
            [IO.File]::WriteAllText($passwordFile, (ConvertFrom-SecureStringPlain $password))
            $unattended = @("unattended", "install", $Name,
                "--iso=$IsoPath", "--image-index=$ImageIndex",
                "--user=$User", "--user-password-file=$passwordFile", "--admin-password-file=$passwordFile",
                "--full-user-name=Synthaea Lab", "--locale=$Locale", "--country=$Country",
                "--hostname=synthaea-drv.lab.local", "--install-additions")
            if (-not $NoStart) { $unattended += "--start-vm=gui" }
            Invoke-Native $vbm $unattended
        } finally {
            Remove-Item -LiteralPath $passwordFile -Force -ErrorAction SilentlyContinue
        }
        Write-Host "Unattended install running; it reboots a few times (about 15-20 minutes)."
    }
} catch {
    Write-Warning "creation failed, removing the half-built VM: $_"
    & $vbm unregistervm $Name --delete 2>$null | Out-Null
    throw
}

Write-Host ""
Write-Host "Next, inside the guest, from an elevated PowerShell:"
Write-Host "  powershell -ExecutionPolicy Bypass -File \\VBoxSvr\$LabShareName\driver\prepare-driver-vm.ps1"
Write-Host "then reboot the guest, and from the host:"
Write-Host "  .\lab\driver\snapshot-driver-vm.ps1 -Name $Name -Take clean"
Write-Host "Kernel debugger: windbg -k com:pipe,port=\\.\pipe\$Name-kd,resets=0,reconnect"
