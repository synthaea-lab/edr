<#
.SYNOPSIS
    Takes, restores or lists snapshots of the driver test VM (host side).

.DESCRIPTION
    ADR-0012: a clean snapshot before each driver load, so a bluescreen or a
    wedged filter costs one restore. A snapshot of a running VM keeps its
    memory, so -Restore puts the guest back exactly as it was, running.

    Two hypervisors, one interface:
      - VirtualBox (default): the VM is named by -Name, driven by VBoxManage;
      - VMware Workstation: pass -Vmx <path to the .vmx>, driven by vmrun.
        Player has no snapshots.

.EXAMPLE
    .\snapshot-driver-vm.ps1 -Take clean
    .\snapshot-driver-vm.ps1 -Take pre-load
    .\snapshot-driver-vm.ps1 -Restore pre-load
    .\snapshot-driver-vm.ps1 -List
    .\snapshot-driver-vm.ps1 -Vmx "D:\VMs\win11-driver\win11-driver.vmx" -Take pre-load
#>
[CmdletBinding(DefaultParameterSetName = "List")]
param(
    [string]$Name = "synthaea-driver-$($env:USERNAME.ToLower())",
    [string]$Vmx,
    [Parameter(ParameterSetName = "Take", Mandatory)][string]$Take,
    [Parameter(ParameterSetName = "Restore", Mandatory)][string]$Restore,
    [Parameter(ParameterSetName = "List")][switch]$List
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common-driver.ps1")

# -- VirtualBox ----------------------------------------------------------------

function Get-VBoxState {
    $line = & $script:vbm showvminfo $Name --machinereadable | Where-Object { $_ -like "VMState=*" }
    if ($LASTEXITCODE -ne 0) { throw "no VirtualBox VM named $Name" }
    $line -replace '^VMState="(.*)"$', '$1'
}

function Get-VBoxSnapshots {
    & $script:vbm snapshot $Name list --machinereadable |
        Where-Object { $_ -match '^SnapshotName(-\d+)*="(.*)"$' } |
        ForEach-Object { $_ -replace '^SnapshotName(-\d+)*="(.*)"$', '$2' }
}

function Invoke-VBoxTake([string]$Label) {
    $snapArgs = @("snapshot", $Name, "take", $Label)
    if ((Get-VBoxState) -eq "running") { $snapArgs += "--live" }
    Invoke-Native $script:vbm $snapArgs
}

function Invoke-VBoxRestore([string]$Target) {
    if (@("poweroff", "saved", "aborted") -notcontains (Get-VBoxState)) {
        Invoke-Native $script:vbm @("controlvm", $Name, "poweroff")
        Start-Sleep -Seconds 2
    }
    Invoke-Native $script:vbm @("snapshot", $Name, "restore", $Target)
    Invoke-Native $script:vbm @("startvm", $Name, "--type=gui")
}

# -- VMware Workstation --------------------------------------------------------

function Get-VmwSnapshots {
    # First line is "Total snapshots: N"; one name per line after it.
    $out = & $script:vmrun -T ws listSnapshots $Vmx
    if ($LASTEXITCODE -ne 0) { throw "vmrun listSnapshots failed for $Vmx : $out" }
    @($out | Select-Object -Skip 1 | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
}

function Test-VmwRunning {
    $running = & $script:vmrun list | Select-Object -Skip 1
    [bool]($running | Where-Object { "$_".Trim() -ieq $Vmx })
}

function Invoke-VmwRestore([string]$Target) {
    Invoke-Native $script:vmrun @("-T", "ws", "revertToSnapshot", $Vmx, $Target)
    # A snapshot of a running VM reverts to a suspended state, not a running one.
    if (-not (Test-VmwRunning)) { Invoke-Native $script:vmrun @("-T", "ws", "start", $Vmx, "gui") }
}

# -- Dispatch ------------------------------------------------------------------

if ($Vmx) {
    $Vmx = (Resolve-Path $Vmx).Path
    $vmrun = Get-VmRun
    $label = $Vmx
} else {
    $vbm = Get-VBoxManage
    $label = $Name
}

switch ($PSCmdlet.ParameterSetName) {
    "Take" {
        # A label reused on purpose (pre-load before every load) gets a
        # timestamp, so older snapshots stay restorable.
        $snapshot = "$Take-" + (Get-Date -Format "yyyyMMdd-HHmmss")
        if ($Vmx) { Invoke-Native $vmrun @("-T", "ws", "snapshot", $Vmx, $snapshot) } else { Invoke-VBoxTake $snapshot }
        Write-Host "snapshot $snapshot taken on $label"
    }
    "Restore" {
        $names = if ($Vmx) { Get-VmwSnapshots } else { Get-VBoxSnapshots }
        $target = $names | Where-Object { $_ -eq $Restore -or $_ -like "$Restore-*" } | Sort-Object | Select-Object -Last 1
        if (-not $target) { throw "no snapshot matching '$Restore' on $label (have: $($names -join ', '))" }
        if ($Vmx) { Invoke-VmwRestore $target } else { Invoke-VBoxRestore $target }
        Write-Host "restored $target and started $label"
    }
    default {
        if ($Vmx) { Get-VmwSnapshots } else { & $vbm snapshot $Name list }
    }
}
