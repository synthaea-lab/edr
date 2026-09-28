<#
.SYNOPSIS
    Takes, restores or lists snapshots of the driver test VM (host side).

.DESCRIPTION
    ADR-0012: a clean snapshot before each driver load, so a bluescreen or a
    wedged filter costs one restore. -Take on a running VM takes a live
    snapshot (memory included), so -Restore puts the guest back exactly as
    it was, already running.

.EXAMPLE
    .\snapshot-driver-vm.ps1 -Take clean
    .\snapshot-driver-vm.ps1 -Take pre-load
    .\snapshot-driver-vm.ps1 -Restore pre-load
    .\snapshot-driver-vm.ps1 -List
#>
[CmdletBinding(DefaultParameterSetName = "List")]
param(
    [string]$Name = "synthaea-driver-$($env:USERNAME.ToLower())",
    [Parameter(ParameterSetName = "Take", Mandatory)][string]$Take,
    [Parameter(ParameterSetName = "Restore", Mandatory)][string]$Restore,
    [Parameter(ParameterSetName = "List")][switch]$List
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common-driver.ps1")

$vbm = Get-VBoxManage

function Get-VmState {
    $line = & $vbm showvminfo $Name --machinereadable | Where-Object { $_ -like "VMState=*" }
    if ($LASTEXITCODE -ne 0) { throw "no VM named $Name" }
    $line -replace '^VMState="(.*)"$', '$1'
}

switch ($PSCmdlet.ParameterSetName) {
    "Take" {
        # A label reused on purpose (pre-load before every load) gets a
        # timestamp, so older snapshots stay restorable.
        $label = "$Take-" + (Get-Date -Format "yyyyMMdd-HHmmss")
        $snapArgs = @("snapshot", $Name, "take", $label)
        if ((Get-VmState) -eq "running") { $snapArgs += "--live" }
        Invoke-Native $vbm $snapArgs
        Write-Host "snapshot $label taken"
    }
    "Restore" {
        $names = & $vbm snapshot $Name list --machinereadable |
            Where-Object { $_ -match '^SnapshotName(-\d+)*="(.*)"$' } |
            ForEach-Object { $_ -replace '^SnapshotName(-\d+)*="(.*)"$', '$2' }
        $target = $names | Where-Object { $_ -eq $Restore -or $_ -like "$Restore-*" } | Sort-Object | Select-Object -Last 1
        if (-not $target) { throw "no snapshot matching '$Restore' on $Name (have: $($names -join ', '))" }
        if ((Get-VmState) -ne "poweroff" -and (Get-VmState) -ne "saved" -and (Get-VmState) -ne "aborted") {
            Invoke-Native $vbm @("controlvm", $Name, "poweroff")
            Start-Sleep -Seconds 2
        }
        Invoke-Native $vbm @("snapshot", $Name, "restore", $target)
        Invoke-Native $vbm @("startvm", $Name, "--type=gui")
        Write-Host "restored $target and started $Name"
    }
    default {
        & $vbm snapshot $Name list
    }
}
