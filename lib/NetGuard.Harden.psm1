<#
    NetGuard.Harden - the platform-neutral hardening ENGINE.

    Audit, scoring and script generation live here. The control catalogues are
    data supplied by each provider (Get-NGHardeningChecks), so adding a control
    means adding a row, and adding a platform means adding a catalogue - never
    editing this file.

    This module NEVER applies a change. It writes scripts for a human to review
    and run. That boundary is deliberate: a background process that silently
    reconfigures security settings is indistinguishable from malware, and an
    automated change that breaks a VPN at 3am is worse than the gap it closed.

    A control row must provide:
      Id, Tier (1-3), Weight, Category, Title, Rationale, Risk,
      Test      scriptblock returning $true when already compliant
      Apply     code to become compliant
      Rollback  code to return to the prior state
#>

# Dependencies are loaded by Import-NGStack (lib/NetGuard.Platform.psm1),
# in order, exactly once. This module deliberately does NOT import its
# siblings: an Import-Module -Force from inside a module unloads and
# reloads the shared module graph mid-import, discarding module-scoped
# state and breaking command resolution in ways that only show up at
# runtime. Load order belongs to one place, not nine.
function Invoke-NGHardeningAudit {
    <#
        Runs every check's Test and returns per-check results plus a weighted score.

        A check whose Test THROWS is reported as 'error', never as compliant. An
        unknown control must not inflate the score - that is the difference
        between a low score you act on and a high score that is a lie.
    #>
    [CmdletBinding()]
    param([int[]]$Tiers = @(1, 2, 3))

    if (-not (Get-Command Get-NGHardeningChecks -ErrorAction SilentlyContinue)) {
        throw 'No hardening catalogue is loaded. Import a provider first (Import-NGProvider).'
    }

    $results = New-Object System.Collections.Generic.List[psobject]
    foreach ($c in (Get-NGHardeningChecks)) {
        if ($c.Tier -notin $Tiers) { continue }
        $state = 'unknown'; $err = $null

        # A control can declare itself irrelevant to this host via an optional
        # Applicable block - no SSH daemon means the SSH controls are not a
        # failure, an error, or a pass. Scoring a host down for not hardening
        # software it does not run makes the score meaningless, and reporting it
        # as 'error' buries the controls that genuinely could not be evaluated.
        $applicable = $true
        if ($c.PSObject.Properties['Applicable'] -and $c.Applicable) {
            try { $applicable = [bool](& $c.Applicable) } catch { $applicable = $true }
        }
        if (-not $applicable) {
            $results.Add([pscustomobject]@{
                    id = $c.Id; tier = $c.Tier; category = $c.Category; title = $c.Title
                    weight = $c.Weight; state = 'n/a'; error = $null
                    risk = $c.Risk; rationale = $c.Rationale
                })
            continue
        }

        try {
            $ok = & $c.Test
            $state = if ($ok) { 'pass' } else { 'fail' }
        }
        catch {
            $state = 'error'
            $err = $_.Exception.Message
        }
        $results.Add([pscustomobject]@{
                id        = $c.Id
                tier      = $c.Tier
                category  = $c.Category
                title     = $c.Title
                weight    = $c.Weight
                state     = $state
                error     = $err
                risk      = $c.Risk
                rationale = $c.Rationale
            })
    }

    $applicable = @($results | Where-Object { $_.state -in 'pass', 'fail' })
    $totalWeight = 0; $earned = 0
    foreach ($r in $applicable) {
        $totalWeight += [int]$r.weight
        if ($r.state -eq 'pass') { $earned += [int]$r.weight }
    }
    $score = if ($totalWeight -gt 0) { [math]::Round(($earned / $totalWeight) * 100, 1) } else { 0 }

    [pscustomobject]@{
        collectedAt  = (Get-Date).ToUniversalTime().ToString('o')
        hostName     = [System.Net.Dns]::GetHostName()
        platform     = (Get-NGPlatform)
        provider     = (Get-NGLoadedProvider)
        score        = $score
        earnedWeight = $earned
        totalWeight  = $totalWeight
        passed       = (Get-NGCount @($results | Where-Object { $_.state -eq 'pass' }))
        failed       = (Get-NGCount @($results | Where-Object { $_.state -eq 'fail' }))
        errored      = (Get-NGCount @($results | Where-Object { $_.state -eq 'error' }))
        notApplicable = (Get-NGCount @($results | Where-Object { $_.state -eq 'n/a' }))
        checks       = @($results)
    }
}

function New-NGRemediationScript {
    <#
        Emits Apply-TierN.ps1 and Rollback-TierN.ps1 for the checks that are
        currently FAILING. Only failing checks are included, so re-running the
        audit shrinks the script rather than reapplying settled controls.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Audit,
        [Parameter(Mandatory = $true)][ValidateSet(1, 2, 3)][int]$Tier,
        [string]$OutputDirectory
    )
    if (-not $OutputDirectory) { $OutputDirectory = Get-NGPath 'harden' }
    if (-not (Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }

    $allChecks = Get-NGHardeningChecks
    $failingIds = @($Audit.checks | Where-Object { $_.tier -eq $Tier -and $_.state -eq 'fail' } | ForEach-Object { $_.id })
    $todo = @($allChecks | Where-Object { $_.Id -in $failingIds })

    $applyPath = Join-Path $OutputDirectory "Apply-Tier$Tier.ps1"
    $rollbackPath = Join-Path $OutputDirectory "Rollback-Tier$Tier.ps1"

    if ((Get-NGCount $todo) -eq 0) {
        $msg = "# Tier $Tier : every check already passes as of $(Get-Date -Format 'u'). Nothing to apply.`n"
        Set-Content -LiteralPath $applyPath -Value $msg -Encoding utf8
        Set-Content -LiteralPath $rollbackPath -Value $msg -Encoding utf8
        return [pscustomobject]@{ tier = $Tier; count = 0; apply = $applyPath; rollback = $rollbackPath }
    }

    $tierNote = switch ($Tier) {
        1 { 'Safe. No user-visible impact expected on a normal workstation.' }
        2 { 'MODERATE RISK. Can break remote access, legacy file sharing and older clients. Read each warning.' }
        3 { 'AGGRESSIVE. Enterprise-grade controls, applied in audit/complain mode first. Expect tuning.' }
    }
    $preamble = ''
    if (Get-Command Get-NGRemediationPreamble -ErrorAction SilentlyContinue) {
        $preamble = Get-NGRemediationPreamble
    }

    # ---- Apply script
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<#')
    [void]$sb.AppendLine("    NetGuard hardening - Tier $Tier")
    [void]$sb.AppendLine("    Generated $(Get-Date -Format 'u') for $($Audit.hostName) ($($Audit.platform))")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("    $tierNote")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("    Applies $(Get-NGCount $todo) control(s) that are currently FAILING.")
    [void]$sb.AppendLine("    Undo everything here with Rollback-Tier$Tier.ps1")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('    Review this file before running it. It changes security settings.')
    [void]$sb.AppendLine('#>')
    [void]$sb.AppendLine('')
    foreach ($line in ($preamble -split "`r?`n")) { [void]$sb.AppendLine($line) }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("Write-Host 'NetGuard Tier $Tier hardening' -ForegroundColor Cyan")
    [void]$sb.AppendLine("Write-Host '$($tierNote -replace "'", "''")' -ForegroundColor Yellow")
    [void]$sb.AppendLine('Write-Host ""')
    [void]$sb.AppendLine('$confirm = Read-Host "Type APPLY to continue"')
    [void]$sb.AppendLine("if (`$confirm -ne 'APPLY') { Write-Host 'Aborted.'; exit 1 }")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('$applied = @(); $failed = @()')
    [void]$sb.AppendLine('')

    foreach ($c in $todo) {
        [void]$sb.AppendLine('# ' + ('=' * 74))
        [void]$sb.AppendLine("# $($c.Id) - $($c.Title)")
        [void]$sb.AppendLine("# Category: $($c.Category) | Weight: $($c.Weight)")
        [void]$sb.AppendLine('#')
        foreach ($line in (Split-NGText -Text $c.Rationale -Width 95)) { [void]$sb.AppendLine("# WHY:  $line") }
        foreach ($line in (Split-NGText -Text $c.Risk -Width 95)) { [void]$sb.AppendLine("# RISK: $line") }
        [void]$sb.AppendLine('# ' + ('=' * 74))
        [void]$sb.AppendLine("Write-Host ''")
        [void]$sb.AppendLine("Write-Host '[$($c.Id)] $($c.Title -replace "'", "''")' -ForegroundColor Cyan")
        [void]$sb.AppendLine('try {')
        # Emitted verbatim with NO added indentation: indenting a line would put
        # whitespace before a here-string terminator ("@), which is a parse error.
        foreach ($line in ($c.Apply -split "`r?`n")) { [void]$sb.AppendLine($line) }
        [void]$sb.AppendLine("    `$applied += '$($c.Id)'")
        [void]$sb.AppendLine("    Write-Host '  OK' -ForegroundColor Green")
        [void]$sb.AppendLine('}')
        [void]$sb.AppendLine('catch {')
        [void]$sb.AppendLine("    `$failed += '$($c.Id)'")
        [void]$sb.AppendLine('    Write-Warning "  FAILED: $($_.Exception.Message)"')
        [void]$sb.AppendLine('}')
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('Write-Host ""')
    [void]$sb.AppendLine('Write-Host "Applied: $($applied.Count)  Failed: $($failed.Count)" -ForegroundColor Cyan')
    [void]$sb.AppendLine('if ($failed.Count -gt 0) { Write-Warning "Failed: $($failed -join '', '')" }')
    [void]$sb.AppendLine('Write-Host "Re-run the hardening agent to confirm the new score."')
    Set-Content -LiteralPath $applyPath -Value $sb.ToString() -Encoding utf8

    # ---- Rollback script
    $rb = New-Object System.Text.StringBuilder
    [void]$rb.AppendLine('<#')
    [void]$rb.AppendLine("    NetGuard hardening ROLLBACK - Tier $Tier")
    [void]$rb.AppendLine("    Generated $(Get-Date -Format 'u') for $($Audit.hostName)")
    [void]$rb.AppendLine('')
    [void]$rb.AppendLine("    Reverses what Apply-Tier$Tier.ps1 changes. A few controls are")
    [void]$rb.AppendLine('    deliberately NOT reversed because doing so would reintroduce a known')
    [void]$rb.AppendLine('    weakness; those print a note instead.')
    [void]$rb.AppendLine('#>')
    [void]$rb.AppendLine('')
    [void]$rb.AppendLine("`$ErrorActionPreference = 'Continue'")
    [void]$rb.AppendLine('$confirm = Read-Host "Type ROLLBACK to undo Tier ' + $Tier + ' changes"')
    [void]$rb.AppendLine("if (`$confirm -ne 'ROLLBACK') { Write-Host 'Aborted.'; exit 1 }")
    [void]$rb.AppendLine('')
    foreach ($c in $todo) {
        [void]$rb.AppendLine("# --- $($c.Id) - $($c.Title)")
        [void]$rb.AppendLine("Write-Host 'Reverting [$($c.Id)]' -ForegroundColor Yellow")
        [void]$rb.AppendLine('try {')
        foreach ($line in ($c.Rollback -split "`r?`n")) { [void]$rb.AppendLine($line) }
        [void]$rb.AppendLine('}')
        [void]$rb.AppendLine('catch { Write-Warning "  failed: $($_.Exception.Message)" }')
        [void]$rb.AppendLine('')
    }
    [void]$rb.AppendLine('Write-Host "Rollback complete. A reboot may be required." -ForegroundColor Cyan')
    Set-Content -LiteralPath $rollbackPath -Value $rb.ToString() -Encoding utf8

    [pscustomobject]@{ tier = $Tier; count = (Get-NGCount $todo); apply = $applyPath; rollback = $rollbackPath }
}

function Split-NGText {
    <#
        Word-wraps a string for comment blocks.

        Done by hand rather than with a lookbehind regex because the regex form
        silently drops text when a single word exceeds the width.
    #>
    param([string]$Text, [int]$Width = 95)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @('') }
    $words = $Text -split '\s+'
    $lines = New-Object System.Collections.Generic.List[string]
    $cur = ''
    foreach ($w in $words) {
        if ($cur.Length -eq 0) { $cur = $w }
        elseif (($cur.Length + 1 + $w.Length) -le $Width) { $cur = "$cur $w" }
        else { $lines.Add($cur); $cur = $w }
    }
    if ($cur) { $lines.Add($cur) }
    , @($lines)
}

function Find-NGHardeningFindings {
    <#
        Turns audit results into findings. Reports the score as one rolled-up
        finding plus a regression alert - the full per-control detail belongs in
        the weekly report, not in a page at 2am.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Audit)
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'hardening'

    $prev = Get-NGState -Name 'hardening-score' -Default $null
    $delta = ''
    if ($prev -and $null -ne $prev.score) {
        $d = [math]::Round([double]$Audit.score - [double]$prev.score, 1)
        if ($d -gt 0) { $delta = " (up $d points from $($prev.score))" }
        elseif ($d -lt 0) { $delta = " (DOWN $([math]::Abs($d)) points from $($prev.score))" }
        else { $delta = ' (unchanged)' }

        # A falling score means a control that used to pass now fails. That is
        # drift, and drift on a security control deserves its own alert
        # regardless of the control's own severity.
        if ($d -le -5) {
            $regressed = @()
            foreach ($c in $Audit.checks) {
                if ($c.state -ne 'fail') { continue }
                $was = @($prev.checks | Where-Object { $_.id -eq $c.id })
                if ($was -and $was[0].state -eq 'pass') { $regressed += $c.title }
            }
            $f.Add((New-NGFinding -Category 'Hardening' -Severity 'High' -Agent $agentId `
                        -Title "Hardening score dropped $([math]::Abs($d)) points to $($Audit.score)/100" `
                        -Detail ("Controls that previously passed and now fail:`n- " + (($regressed | Select-Object -First 10) -join "`n- ")) `
                        -Recommendation 'Something changed these settings. If it was not you or a system update, investigate before simply reapplying the hardening script.' `
                        -Evidence @{ from = $prev.score; to = $Audit.score; regressed = $regressed } `
                        -FingerprintSeed "score-regression|$($Audit.score)"))
        }
    }

    $sev = if ($Audit.score -lt 50) { 'High' } elseif ($Audit.score -lt 75) { 'Medium' } else { 'Info' }
    $failedT1 = @($Audit.checks | Where-Object { $_.tier -eq 1 -and $_.state -eq 'fail' })

    $f.Add((New-NGFinding -Category 'Hardening' -Severity $sev -Agent $agentId `
                -Title "Hardening score: $($Audit.score)/100$delta" `
                -Detail ("$($Audit.passed) passed, $($Audit.failed) failed, $($Audit.errored) could not be evaluated.`n`n" +
                    "Tier 1 (safe) failures still outstanding: $(Get-NGCount $failedT1)`n" +
                    (($failedT1 | ForEach-Object { "- [$($_.id)] $($_.title)" }) -join "`n")) `
                -Recommendation 'Review harden/Apply-Tier1.ps1, then run it with administrative privilege. Every change has a matching Rollback script.' `
                -Evidence @{ score = $Audit.score; passed = $Audit.passed; failed = $Audit.failed } `
                -FingerprintSeed 'hardening-score-summary'))

    Set-NGState -Name 'hardening-score' -Value $Audit
    , @($f)
}

Export-ModuleMember -Function *
