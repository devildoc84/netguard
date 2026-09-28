<#
.SYNOPSIS
    Shows the raw log lines behind each event category, so you can see exactly
    what a detection rule matched.

.DESCRIPTION
    Event rules are the easiest place to generate confident nonsense: a regex
    that looks specific will happily match routine housekeeping. This prints the
    matching text for every category so a false positive is obvious rather than
    arriving as a Critical alert at 3am.

.EXAMPLE
    pwsh -File tests/Probe-Events.ps1 -Minutes 60
#>
[CmdletBinding()]
param([int]$Minutes = 20)

$ErrorActionPreference = 'Continue'
$NGRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $NGRoot 'lib/NetGuard.Platform.psm1') -DisableNameChecking -Global -Force
Import-NGStack -Force | Out-Null

Write-Host ''
Write-Host "Event probe - last $Minutes minutes on $(Get-NGPlatform)" -ForegroundColor Cyan

$ev = Get-NGSecurityEvents -SinceMinutes $Minutes

foreach ($cat in 'failedLogons', 'logCleared', 'accountChanges', 'newServices',
    'avDetections', 'suspiciousExecution', 'remoteLogons') {
    $items = @($ev.$cat)
    $color = if ($items.Count -gt 0) { 'Yellow' } else { 'DarkGray' }
    Write-Host ''
    Write-Host "== $cat ($($items.Count))" -ForegroundColor $color
    foreach ($i in ($items | Select-Object -First 10)) {
        # Print every property so it is obvious which field the rule keyed on.
        $parts = foreach ($prop in $i.PSObject.Properties) {
            $v = "$($prop.Value)"
            if ($v.Length -gt 160) { $v = $v.Substring(0, 160) + '...' }
            "$($prop.Name)=$v"
        }
        Write-Host "   - $($parts -join ' | ')"
    }
    if ($items.Count -gt 10) { Write-Host "   ... and $($items.Count - 10) more" -ForegroundColor DarkGray }
}

Write-Host ''
Write-Host '== Findings these would produce' -ForegroundColor Cyan
$findings = Find-NGEventFindings -Events $ev
if ((Get-NGCount $findings) -eq 0) {
    Write-Host '   (none)' -ForegroundColor DarkGray
}
else {
    foreach ($f in ($findings | Sort-Object severityRank -Descending)) {
        Write-Host ("   [{0,-8}] {1}" -f $f.severity, $f.title)
    }
}
Write-Host ''
