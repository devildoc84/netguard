<#
.SYNOPSIS
    NetGuard Hardening - daily posture audit, scoring and remediation scripts.

.DESCRIPTION
    Runs daily. Collects the full security posture, scores the host against the
    control catalogue, and regenerates the tiered Apply/Rollback scripts so they
    always reflect what is currently non-compliant.

    This agent NEVER applies a change. It writes scripts and you run them. That
    boundary is deliberate: a background process that silently reconfigures
    security settings is indistinguishable from malware, and an automated change
    that breaks VMware or your VPN at 3am is worse than the gap it closed.

    It also watches for score REGRESSION. A control that used to pass and now
    fails means something changed the configuration, and that is worth an alert
    independently of the control's own severity.

.PARAMETER GenerateScripts
    Regenerate harden\Apply-Tier*.ps1 and Rollback-Tier*.ps1. Default on.

.EXAMPLE
    .\Invoke-HardeningAgent.ps1 -NoAlert
#>
[CmdletBinding()]
param(
    [bool]$GenerateScripts = $true,
    [switch]$NoAlert,
    [switch]$NoAI
)

. (Join-Path $PSScriptRoot '_Bootstrap.ps1')

$AGENT = 'hardening'
Write-NGLog "Hardening audit starting (elevated=$(Test-NGElevated))" -Agent $AGENT

if (-not (Test-NGElevated)) {
    Write-NGLog 'Not elevated: BitLocker, Secure Boot, Defender exclusions and several policy checks cannot be read and will report as unknown rather than as failures.' -Level WARN -Agent $AGENT
}

$findings = New-Object System.Collections.Generic.List[psobject]

# --- full posture sweep
$posture = $null
foreach ($f in (Invoke-NGStage -Name 'host-posture' -Agent $AGENT -Body {
            $script:posture = Get-NGHostPosture
            Set-NGState -Name 'posture' -Value $script:posture
            Find-NGPostureFindings -Posture $script:posture
        })) { if ($f) { $findings.Add($f) } }
$posture = $script:posture

# --- scored control audit
$audit = $null
foreach ($f in (Invoke-NGStage -Name 'hardening-audit' -Agent $AGENT -Body {
            $script:audit = Invoke-NGHardeningAudit
            Write-NGLog "Hardening score: $($script:audit.score)/100 ($($script:audit.passed) pass, $($script:audit.failed) fail, $($script:audit.errored) unevaluated)" -Agent $AGENT
            Find-NGHardeningFindings -Audit $script:audit
        })) { if ($f) { $findings.Add($f) } }
$audit = $script:audit

# --- regenerate remediation scripts so they match current reality
if ($GenerateScripts -and $audit) {
    Invoke-NGStage -Name 'generate-scripts' -Agent $AGENT -Body {
        foreach ($tier in 1, 2, 3) {
            $r = New-NGRemediationScript -Audit $script:audit -Tier $tier
            Write-NGLog "Tier $tier : $($r.count) outstanding control(s) -> $(Split-Path $r.apply -Leaf)" -Agent $AGENT
        }
        @()
    } | Out-Null
}

# --- keep the findings ledger from growing without bound
Invoke-NGStage -Name 'ledger-maintenance' -Agent $AGENT -Body {
    $cfg = $null
    try { $cfg = Get-NGConfig } catch { }
    $days = 120
    if ($cfg -and $cfg.retention.findingsDays) { $days = [int]$cfg.retention.findingsDays }
    Compress-NGLedger -RetentionDays $days
    @()
} | Out-Null

$result = Complete-NGRun -Findings $findings -Agent $AGENT -NoAlert:$NoAlert -UseAI:(-not $NoAI)

# Emit findings so the agent is useful interactively; exit 0 keeps Task
# Scheduler from flagging a healthy run as failed.
$result
exit 0
