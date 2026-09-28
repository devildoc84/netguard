<#
.SYNOPSIS
    NetGuard Sentinel - the fast loop. Near-real-time host detections.

.DESCRIPTION
    Runs every 15 minutes. Only cheap, high-signal collectors belong here: the
    full posture sweep takes several seconds and lives in the hardening agent
    instead. Covers security event triage, new network listeners, and hosts-file
    tampering.

    The event window intentionally overlaps the schedule slightly (20 minutes for
    a 15-minute cadence) so an event landing on a boundary is not missed. Dedupe
    by fingerprint in the notifier absorbs the resulting repeats.

.PARAMETER WindowMinutes
    How far back to read the event logs. Keep it above the schedule interval.

.PARAMETER NoAlert
    Collect and record findings without sending anything. Use when tuning.

.EXAMPLE
    .\Invoke-SentinelAgent.ps1 -NoAlert
#>
[CmdletBinding()]
param(
    [int]$WindowMinutes = 20,
    [switch]$NoAlert,
    [switch]$NoAI
)

. (Join-Path $PSScriptRoot '_Bootstrap.ps1')

$AGENT = 'sentinel'
Write-NGLog "Sentinel starting (window ${WindowMinutes}m, elevated=$(Test-NGElevated))" -Agent $AGENT

if (-not (Test-NGElevated)) {
    Write-NGLog 'Not elevated: the Security event log is unreadable, so authentication, account-change and log-clearing detections are all disabled for this run.' -Level WARN -Agent $AGENT
}

$findings = New-Object System.Collections.Generic.List[psobject]

# --- event log triage (the highest-value signal per second spent)
foreach ($f in (Invoke-NGStage -Name 'security-events' -Agent $AGENT -Body {
            $ev = Get-NGSecurityEvents -SinceMinutes $WindowMinutes
            $cfg = $null
            try { $cfg = Get-NGConfig } catch { }
            $threshold = 10
            if ($cfg -and $cfg.thresholds.failedLogonBurst) { $threshold = [int]$cfg.thresholds.failedLogonBurst }
            Find-NGEventFindings -Events $ev -FailedLogonThreshold $threshold
        })) { if ($f) { $findings.Add($f) } }

# --- new listeners / exposure drift
foreach ($f in (Invoke-NGStage -Name 'listening-ports' -Agent $AGENT -Body {
            Find-NGPortFindings -Ports (Get-NGListeningPorts)
        })) { if ($f) { $findings.Add($f) } }

# --- hosts file integrity
foreach ($f in (Invoke-NGStage -Name 'hosts-file' -Agent $AGENT -Body {
            Find-NGHostsFileFindings -Entries (Get-NGHostsFileEntries)
        })) { if ($f) { $findings.Add($f) } }

# --- liveness of the other agents. Checked here because Sentinel runs most
#     often, so it notices a dead daily agent soonest.
foreach ($f in (Invoke-NGStage -Name 'heartbeat-check' -Agent $AGENT -Body {
            Test-NGHeartbeat -ExpectedIntervalHours @{ discovery = 26; hardening = 26 }
        })) { if ($f) { $findings.Add($f) } }

$result = Complete-NGRun -Findings $findings -Agent $AGENT -NoAlert:$NoAlert -UseAI:(-not $NoAI)

# Emit findings so the agent is useful interactively; exit 0 keeps Task
# Scheduler from flagging a healthy run as failed.
$result
exit 0
