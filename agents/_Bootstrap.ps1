<#
    Shared agent bootstrap. Dot-sourced by every agent so module loading, error
    handling and run accounting stay identical across them.

    Deliberately does NOT use $ErrorActionPreference='Stop': an agent must survive
    one broken collector and still report everything else. A monitoring run that
    aborts halfway produces silence, and silence reads as "all clear".
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$NGRootDir = Split-Path -Parent $PSScriptRoot
$NGLibDir = Join-Path $NGRootDir 'lib'

# One loader, one load order. Import-NGStack pulls in Core, the platform
# provider and the remaining modules in dependency order. Modules never import
# each other - see the note in NetGuard.Platform.psm1 for why.
Import-Module (Join-Path $NGLibDir 'NetGuard.Platform.psm1') -DisableNameChecking -Global
$NGStack = Import-NGStack
if (-not $NGStack.provider) {
    throw "No NetGuard provider could be loaded for platform '$($NGStack.platform)'."
}

Initialize-NGTree

function Invoke-NGStage {
    <#
        Runs one named collection/detection stage in isolation.

        A stage that throws is reported as a finding rather than being swallowed:
        a detector that silently stops working is worse than one that fails loudly,
        because the absence of alerts looks identical to the absence of problems.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [string]$Agent = 'agent'
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $out = & $Body
        $sw.Stop()
        Write-NGLog "$Name completed in $($sw.ElapsedMilliseconds)ms" -Level DEBUG -Agent $Agent -Quiet
        , @($out)
    }
    catch {
        $sw.Stop()
        Write-NGLog "$Name FAILED: $($_.Exception.Message)" -Level ERROR -Agent $Agent
        , @(New-NGFinding -Category 'Availability' -Severity 'Medium' -Agent $Agent `
                -Title "NetGuard stage '$Name' failed" `
                -Detail "$($_.Exception.Message)`n`nAt: $($_.InvocationInfo.PositionMessage)" `
                -Recommendation 'A failing collector is a blind spot. Check logs\netguard-*.jsonl and whether the agent is running with enough privilege.' `
                -FingerprintSeed "stage-failure|$Name")
    }
}

function Complete-NGRun {
    <#
        Common tail for every agent: ship findings, record liveness, flush the
        suppression digest, and leave a run record for the weekly report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()]$Findings,
        [Parameter(Mandatory = $true)][string]$Agent,
        [switch]$NoAlert,
        [switch]$UseAI
    )
    $all = @($Findings | Where-Object { $null -ne $_ })
    $cfg = $null
    try { $cfg = Get-NGConfig } catch { }

    # AI triage only for findings that would actually reach someone. Enriching an
    # Info-level finding nobody will be paged about is pure cost.
    if ($UseAI -and $cfg -and $cfg.ai.enabled) {
        $floor = Get-NGSeverityRank $cfg.ai.triageMinSeverity
        $toTriage = @($all | Where-Object { [int]$_.severityRank -ge $floor })
        $rest = @($all | Where-Object { [int]$_.severityRank -lt $floor })
        if ((Get-NGCount $toTriage) -gt 0) {
            Write-NGLog "AI-triaging $(Get-NGCount $toTriage) finding(s)" -Agent $Agent
            $triaged = @($toTriage | Invoke-NGTriage -Model $cfg.ai.triageModel)
            $all = @($triaged) + @($rest)
        }
    }

    foreach ($f in $all) { $null = $f | Add-NGFinding }

    if (-not $NoAlert) {
        foreach ($f in $all) { $null = $f | Send-NGAlert }
        Send-NGOverflowDigest
    }

    Send-NGHeartbeat -Agent $Agent

    $counts = [ordered]@{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') {
        $counts[$s] = (Get-NGCount @($all | Where-Object { $_.severity -eq $s }))
    }
    Set-NGState -Name "lastrun-$Agent" -Value ([pscustomobject]@{
            at       = (Get-Date).ToUniversalTime().ToString('o')
            findings = (Get-NGCount $all)
            bySeverity = [pscustomobject]$counts
        })

    $summary = (($counts.Keys | Where-Object { $counts[$_] -gt 0 } | ForEach-Object { "$_=$($counts[$_])" }) -join ' ')
    if (-not $summary) { $summary = 'nothing to report' }
    Write-NGLog "$Agent run complete: $summary" -Agent $Agent
    $all
}
