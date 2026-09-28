<#
.SYNOPSIS
    Creates (or reuses) this developer's driver test-signing certificate.

.DESCRIPTION
    A self-signed code-signing certificate in CurrentUser\My, exported (public
    part only) to target\driver\cert\synthaea-driver-test.cer, where the VM
    reads it through the \\VBoxSvr\synthaea share. The private key never
    leaves the host's certificate store.

    A driver signed with it loads only where the certificate is trusted AND
    test-signing is on, i.e. in the developer's own test VM
    (prepare-driver-vm.ps1). Production signing is ADR-0012's separate,
    MVI-gated path.

    Idempotent: an existing, still-valid certificate with the same subject is
    reused, so VMs that already trust it keep working.
#>
[CmdletBinding()]
param(
    [int]$ValidYears = 2
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common-driver.ps1")

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
    Where-Object { $_.Subject -eq $DriverCertSubject -and $_.NotAfter -gt (Get-Date).AddDays(7) } |
    Sort-Object NotAfter -Descending | Select-Object -First 1

if ($cert) {
    Write-Host "reusing $($cert.Subject) ($($cert.Thumbprint), valid until $($cert.NotAfter.ToString('yyyy-MM-dd')))"
} else {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $DriverCertSubject `
        -CertStoreLocation Cert:\CurrentUser\My -HashAlgorithm SHA256 -KeyLength 3072 `
        -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears($ValidYears)
    Write-Host "created $($cert.Subject) ($($cert.Thumbprint))"
}

$certDir = Join-Path (Get-DriverOutDir) "cert"
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
$cer = Join-Path $certDir "synthaea-driver-test.cer"
Export-Certificate -Cert $cert -FilePath $cer -Type CERT | Out-Null
Write-Host "public certificate: $cer"
