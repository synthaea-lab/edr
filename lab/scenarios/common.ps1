<#
.SYNOPSIS
    Helpers shared by the Windows scenarios, dot-sourced by each of them.

.DESCRIPTION
    Every .ps1 under lab/ and demo/ must run on a stock Windows PowerShell 5.1
    under any locale (#433), which rules out three things:
      - Non-ASCII characters. PowerShell 5.1 reads a BOM-less file as the ANSI
        code page, and an em dash decodes to a closing smart quote that breaks
        parsing. The scripts stay ASCII-only (tools/check-ps1-ascii.py).
      - Locale-formatted literals. `schtasks /SD 12/31/2099` is rejected on a
        French locale ("date de debut incorrecte"); use Get-FarFutureDate.
      - Unchecked native calls. A scenario that prints "created" after the tool
        failed cannot validate a detection; use Invoke-Native.
      - Native prompts. Invoke-Native feeds the tool one empty line and closes
        its stdin, so a prompt gets Enter instead of waiting forever on a
        console whose output goes to Out-Null. A tool that needs real input
        then fails loudly rather than hanging: `schtasks /Change` asks for the
        run-as password even with /IT or /RU, hung the first cut of the
        task-hijack scenario, and rejects the empty line (lab, fr-FR,
        2026-09-25). Rewrite a task's action with Set-ScheduledTask instead.
#>

function Invoke-Native {
    <#
    .SYNOPSIS
        Runs a native tool with one empty line on stdin, discards its output,
        throws on a non-zero exit code. Arguments listed in -Redact (e.g. a password) show as
        *** in the error.
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [string[]]$Redact = @()
    )
    "" | & $FilePath @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $shown = $Arguments | ForEach-Object { if ($Redact -contains $_) { "***" } else { $_ } }
        throw "$FilePath $($shown -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NativeCleanup {
    <#
    .SYNOPSIS
        Cleanup counterpart of Invoke-Native: warns instead of throwing, so one
        failed delete in a `finally` block does not skip the remaining ones.
    #>
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    "" | & $FilePath @Arguments | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  deleted $Description"
    }
    else {
        Write-Warning "could not delete $Description ($FilePath exit code $LASTEXITCODE), remove it by hand"
    }
}

function Get-FarFutureDate {
    <#
    .SYNOPSIS
        A date 70 years out, in the current culture's short date format, which
        is what `schtasks /SD` parses (lab, fr-FR, 2026-09-25: dd/MM/yyyy).
    #>
    (Get-Date).AddYears(70).ToString((Get-Culture).DateTimeFormat.ShortDatePattern)
}
