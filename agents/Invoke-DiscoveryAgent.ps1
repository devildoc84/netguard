<#
.SYNOPSIS
    NetGuard Discovery - network inventory and persistence/integrity drift.

.DESCRIPTION
    Runs hourly. Two jobs that both depend on baselines rather than signatures:

      Network:  sweep the LAN, diff devices against the approved baseline, and
                check the perimeter (external IP, UPnP, gateway exposure).
      Host:     diff autostart entries, local accounts and trusted root
                certificates against their baselines.

    Everything here is read-only against other devices: an ARP/ping sweep and
    reverse DNS. No port scanning, no credentials, nothing installed remotely.
    That keeps it safe to run on a network you share with other people.

    First run records baselines silently instead of alerting on the several
    hundred autostart entries and certificates that already exist.

.PARAMETER SkipSweep
    Use the existing ARP cache instead of priming it with a ping sweep. Faster
    and quieter, but misses idle hosts.

.EXAMPLE
    .\Invoke-DiscoveryAgent.ps1 -NoAlert
#>
[CmdletBinding()]
param(
    [switch]$SkipSweep,
    [switch]$NoAlert,
    [switch]$NoAI
)

. (Join-Path $PSScriptRoot '_Bootstrap.ps1')

$AGENT = 'discovery'
Write-NGLog "Discovery starting (elevated=$(Test-NGElevated))" -Agent $AGENT

$findings = New-Object System.Collections.Generic.List[psobject]

# --- LAN device inventory
foreach ($f in (Invoke-NGStage -Name 'lan-devices' -Agent $AGENT -Body {
            $devices = Get-NGLanDevices -SkipSweep:$SkipSweep
            Write-NGLog "Discovered $(Get-NGCount $devices) device(s) on the LAN" -Agent $AGENT
            Set-NGState -Name 'lan-last-seen' -Value $devices
            Find-NGLanFindings -Devices $devices
        })) { if ($f) { $findings.Add($f) } }

# --- perimeter
foreach ($f in (Invoke-NGStage -Name 'perimeter' -Agent $AGENT -Body {
            $p = Get-NGPerimeter
            Set-NGState -Name 'perimeter' -Value $p
            Find-NGPerimeterFindings -Perimeter $p
        })) { if ($f) { $findings.Add($f) } }

# --- autostart persistence drift
foreach ($f in (Invoke-NGStage -Name 'autoruns' -Agent $AGENT -Body {
            Find-NGAutorunFindings -Autoruns (Get-NGAutoruns)
        })) { if ($f) { $findings.Add($f) } }

# --- local accounts
foreach ($f in (Invoke-NGStage -Name 'accounts' -Agent $AGENT -Body {
            Find-NGAccountFindings -Accounts (Get-NGLocalAccounts)
        })) { if ($f) { $findings.Add($f) } }

# --- trusted root certificate store
foreach ($f in (Invoke-NGStage -Name 'root-certificates' -Agent $AGENT -Body {
            Find-NGCertificateFindings -Certificates (Get-NGTrustedCertificates)
        })) { if ($f) { $findings.Add($f) } }

$result = Complete-NGRun -Findings $findings -Agent $AGENT -NoAlert:$NoAlert -UseAI:(-not $NoAI)

# Emit findings so the agent is useful interactively; exit 0 keeps Task
# Scheduler from flagging a healthy run as failed.
$result
exit 0
