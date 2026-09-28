<#
.SYNOPSIS
    Scan one file, or a folder, on demand.

.DESCRIPTION
    The manual entry point to the same pipeline the watcher uses. Handy before
    running an installer you are unsure about, or for triaging something after
    the fact.

    Scanning never modifies the file. Quarantine only happens if you pass
    -Quarantine, or if the verdict is malicious and -AutoQuarantine is set.

.PARAMETER Path
    File or folder to analyse.

.PARAMETER Quarantine
    Neutralise the file regardless of score.

.PARAMETER Detailed
    Print the full evidence rather than the summary.

.EXAMPLE
    .\Scan-File.ps1 -Path "$env:USERPROFILE\Downloads\setup.exe" -Detailed

.EXAMPLE
    Get-ChildItem ~\Downloads -File | .\Scan-File.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
    [Alias('FullName')]
    [string[]]$Path,

    [switch]$Quarantine,
    [switch]$AutoQuarantine,
    [switch]$Detailed,
    [switch]$NoAI,
    [switch]$Alert
)

begin {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'agents\_Bootstrap.ps1')
    $cfg = $null
    try { $cfg = Get-NGConfig } catch { }
    $useVt = ($cfg -and $cfg.scan.virusTotalEnabled)
    $useAi = (-not $NoAI) -and ($cfg -and $cfg.ai.enabled)
    $threshold = if ($cfg) { [int]$cfg.scan.quarantineThreshold } else { 60 }
    $results = New-Object System.Collections.Generic.List[psobject]
}

process {
    foreach ($p in $Path) {
        $targets = @()
        if (Test-Path -LiteralPath $p -PathType Container) {
            $targets = @(Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        }
        elseif (Test-Path -LiteralPath $p -PathType Leaf) { $targets = @($p) }
        else { Write-Warning "Not found: $p"; continue }

        foreach ($t in $targets) {
            $r = Invoke-NGFileScan -Path $t -SkipVirusTotal:(-not $useVt) -SkipAI:(-not $useAi)
            $results.Add($r)

            $color = switch ($r.verdict) {
                'quarantine' { 'Red' }
                'suspicious' { 'Yellow' }
                default { 'Green' }
            }
            Write-Host ''
            Write-Host ("  {0}" -f $r.name) -ForegroundColor White
            Write-Host ("  verdict: {0}   score: {1}" -f $r.verdict.ToUpper(), $r.score) -ForegroundColor $color
            Write-Host ("  sha256 : {0}" -f $r.sha256) -ForegroundColor DarkGray
            Write-Host ("  type   : {0}" -f $r.fileType) -ForegroundColor DarkGray
            $origin = if ($r.motw.hostUrl) { $r.motw.hostUrl } elseif ($r.motw.referrerUrl) { $r.motw.referrerUrl } else { 'no Mark-of-the-Web' }
            Write-Host ("  origin : {0}" -f $origin) -ForegroundColor DarkGray
            if ((Get-NGCount $r.reasons) -gt 0) {
                Write-Host '  reasons:' -ForegroundColor DarkGray
                foreach ($rs in @($r.reasons)) { Write-Host "    $rs" -ForegroundColor DarkGray }
            }
            if ($r.ai) {
                Write-Host ("  AI     : {0} ({1}) - {2}" -f $r.ai.verdict, $r.ai.confidence, $r.ai.summary) -ForegroundColor Cyan
                if ($r.ai.promptInjectionSuspected) {
                    Write-Host '  NOTE   : this file contains text trying to manipulate an AI analyser.' -ForegroundColor Magenta
                }
            }
            if ($Detailed) {
                Write-Host '  --- full evidence ---' -ForegroundColor DarkGray
                ($r | ConvertTo-Json -Depth 8) -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
            }

            $didQ = $false
            if ($Quarantine -or ($AutoQuarantine -and [int]$r.score -ge $threshold)) {
                $q = Move-NGToQuarantine -ScanResult $r
                $didQ = [bool]$q.quarantined
                if ($didQ) { Write-Host "  quarantined to: $($q.destination)" -ForegroundColor Yellow }
            }

            if ($Alert -and $r.verdict -ne 'allow') {
                $null = (ConvertTo-NGScanFinding -ScanResult $r -Quarantined:$didQ) | Add-NGFinding | Send-NGAlert
            }
        }
    }
}

end {
    Write-Host ''
    $q = (Get-NGCount @($results | Where-Object { $_.verdict -eq 'quarantine' }))
    $s = (Get-NGCount @($results | Where-Object { $_.verdict -eq 'suspicious' }))
    $a = (Get-NGCount @($results | Where-Object { $_.verdict -eq 'allow' }))
    Write-Host ("  Scanned {0}: {1} allow, {2} suspicious, {3} malicious" -f (Get-NGCount $results), $a, $s, $q) -ForegroundColor Cyan
    Send-NGHeartbeat -Agent 'scan'
}
