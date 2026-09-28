<#
.SYNOPSIS
    Helpers shared by the lab\driver scripts (ADR-0012), dot-sourced by each.

.DESCRIPTION
    Same rules as lab\scenarios\common.ps1, which this loads: Windows
    PowerShell 5.1, ASCII only, every native call checked (Invoke-Native).
#>

. (Join-Path $PSScriptRoot "..\scenarios\common.ps1")

# The test certificate's subject. Per developer: each VM trusts its owner's
# certificate only, and nothing signed with it loads outside test-signing.
$DriverCertSubject = "CN=Synthaea Driver Test ($($env:USERNAME))"

function Get-RepoRoot {
    (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

function Get-DriverOutDir {
    # Build products live under target\ (git-ignored), shared read-only into
    # the VM, so guest-side callers must not try to create it.
    Join-Path (Get-RepoRoot) "target\driver"
}

function Get-VBoxManage {
    $candidates = @()
    if ($env:VBOX_MSI_INSTALL_PATH) { $candidates += Join-Path $env:VBOX_MSI_INSTALL_PATH "VBoxManage.exe" }
    $candidates += "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    throw "VBoxManage.exe not found; install VirtualBox 7 or set VBOX_MSI_INSTALL_PATH"
}

function Find-KitTool([string]$Tool) {
    # Newest version under Windows Kits\10\bin: signtool ships with the SDK,
    # inf2cat only with the WDK (it lives under x86 even on x64 hosts).
    $bin = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $hit = Get-ChildItem -Path $bin -Filter $Tool -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\(x64|x86)\\' } |
        Sort-Object @{ Expression = { $_.FullName -match '\\x64\\' }; Descending = $true }, FullName -Descending |
        Select-Object -First 1
    if ($hit) { $hit.FullName } else { $null }
}

function ConvertFrom-SecureStringPlain([securestring]$Secure) {
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this from an elevated PowerShell."
    }
}

function Assert-InVirtualBox([switch]$Force) {
    # ADR-0012: never on a host machine. A driver bug bluescreens whatever runs it.
    $model = (Get-CimInstance Win32_ComputerSystem).Model
    if ($model -notmatch "VirtualBox" -and -not $Force) {
        throw "This machine ('$model') is not a VirtualBox guest. Driver tests run in the test-signing VM only (ADR-0012); -Force overrides."
    }
}

function Test-TestSigningOn {
    # SystemStartOptions is locale-independent, unlike `bcdedit /enum` output.
    $options = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control").SystemStartOptions
    $options -match "TESTSIGNING"
}
