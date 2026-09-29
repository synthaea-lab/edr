<#
.SYNOPSIS
    Test-signs a built minifilter into target\driver\package (host side).

.DESCRIPTION
    Copies the .sys and .inf from -DriverDir, then:
      - signs the .sys (embedded signature: what the kernel checks at load);
      - builds the catalog with inf2cat and signs it (the catalog is what
        pnputil checks when driver-load-unload.ps1 installs the INF).
    Both with this developer's test certificate (new-test-cert.ps1). Needs
    the WDK for inf2cat: a package without a catalog is refused here rather
    than left to fail at the install step in the VM (#516 review).

    No timestamp: a test certificate's signatures only need to hold inside
    the test VM, and the VM may have no network.

.PARAMETER DriverDir
    The build output: one .sys and its .inf (e.g. the x64\Debug directory of
    the driver project).

.EXAMPLE
    .\sign-driver.ps1 -DriverDir ..\..\crates\sensors\windows\driver\x64\Debug
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DriverDir
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common-driver.ps1")

$DriverDir = (Resolve-Path $DriverDir).Path
$sys = @(Get-ChildItem -LiteralPath $DriverDir -Filter *.sys)
$inf = @(Get-ChildItem -LiteralPath $DriverDir -Filter *.inf)
if ($sys.Count -ne 1 -or $inf.Count -ne 1) {
    throw "expected exactly one .sys and one .inf in $DriverDir (found $($sys.Count) and $($inf.Count))"
}

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
    Where-Object { $_.Subject -eq $DriverCertSubject -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw "no test certificate '$DriverCertSubject'; run new-test-cert.ps1 first" }

$signtool = Find-KitTool "signtool.exe"
if (-not $signtool) { throw "signtool.exe not found under Windows Kits\10\bin; install the Windows SDK" }
$inf2cat = Find-KitTool "inf2cat.exe"
if (-not $inf2cat) { throw "inf2cat.exe not found under Windows Kits\10\bin; install the WDK (the package needs a signed catalog)" }

$package = Join-Path (Get-DriverOutDir) "package"
if (Test-Path $package) { Remove-Item -LiteralPath $package -Recurse -Force }
New-Item -ItemType Directory -Path $package | Out-Null
Copy-Item -LiteralPath $sys[0].FullName, $inf[0].FullName -Destination $package
$pdb = Join-Path $DriverDir ($sys[0].BaseName + ".pdb")
if (Test-Path $pdb) { Copy-Item -LiteralPath $pdb -Destination $package }

$signArgs = @("sign", "/fd", "SHA256", "/s", "My", "/sha1", $cert.Thumbprint)
$sysOut = Join-Path $package $sys[0].Name
Invoke-Native $signtool ($signArgs + $sysOut)
Write-Host "signed $($sys[0].Name)"

Invoke-Native $inf2cat @("/driver:$package", "/os:10_x64", "/uselocaltime")
$cat = @(Get-ChildItem -LiteralPath $package -Filter *.cat)
if ($cat.Count -ne 1) { throw "inf2cat produced $($cat.Count) catalogs; check the INF's CatalogFile entry" }
Invoke-Native $signtool ($signArgs + $cat[0].FullName)
Write-Host "built and signed $($cat[0].Name)"

# The host doesn't trust the test root, so the status is not Valid here; what
# matters is that the signer is this developer's certificate.
foreach ($file in Get-ChildItem -LiteralPath $package | Where-Object { $_.Extension -in ".sys", ".cat" }) {
    $sig = Get-AuthenticodeSignature -LiteralPath $file.FullName
    if (-not $sig.SignerCertificate -or $sig.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
        throw "$($file.Name) is not signed by $($cert.Thumbprint)"
    }
}
Write-Host "package ready: $package (in the VM: \\VBoxSvr\synthaea\target\driver\package)"
