<#
.SYNOPSIS
    Register (or remove) the NetGuard scheduled jobs on any supported platform.

.DESCRIPTION
    Defines the schedule once, then hands it to the platform provider: Task
    Scheduler on Windows, systemd timers on Linux.

      Sentinel      every 15 min   fast host detections
      Discovery     hourly         LAN inventory, persistence and integrity drift
      Hardening     daily 03:15    posture audit, scoring, remediation scripts
      WeeklyReport  Mon 08:00      report + Discord summary + SMS digest
      Watcher       at logon       download scanner (long-running)

    PRIVILEGE. Sentinel, Discovery, Hardening and WeeklyReport run as
    SYSTEM/root: they need the audit log, disk-encryption state and antivirus
    configuration, none of which an unprivileged user can read.

    The Watcher runs as the ordinary USER on purpose. It parses attacker-supplied
    files all day, and running that as SYSTEM/root would hand any parser bug the
    highest privilege on the machine. Least privilege matters most exactly where
    the untrusted input is.

.PARAMETER Remove
    Unregister every NetGuard job.

.PARAMETER NoWatcher
    Skip the download watcher (useful on a headless server).

.EXAMPLE
    # Windows, from an elevated prompt
    .\install\Register-Tasks.ps1

.EXAMPLE
    # Linux
    sudo pwsh -File ./install/Register-Tasks.ps1

.EXAMPLE
    .\install\Register-Tasks.ps1 -Remove
#>
[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$NoWatcher,
    [string]$WatcherUser
)

$ErrorActionPreference = 'Stop'

$NGRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $NGRoot 'lib/NetGuard.Platform.psm1') -DisableNameChecking -Global
$stack = Import-NGStack

if (-not (Test-NGElevated)) {
    throw 'Register-Tasks must run elevated: as Administrator on Windows, or with sudo on Linux.'
}
if (-not (Get-Command Register-NGSchedule -ErrorAction SilentlyContinue)) {
    throw "The '$($stack.provider)' provider does not implement scheduling. Register the jobs by hand, or add Register-NGSchedule to that provider."
}

# Default the watcher account to whoever invoked this. Under sudo that means the
# real user, not root - registering the watcher as root would defeat the whole
# point of running it unprivileged.
if (-not $WatcherUser) {
    if ((Get-NGPlatform) -eq 'Windows') {
        $WatcherUser = "$env:USERDOMAIN\$env:USERNAME"
    }
    else {
        $WatcherUser = $env:SUDO_USER
        if (-not $WatcherUser) { $WatcherUser = $env:USER }
        if (-not $WatcherUser) { $WatcherUser = 'root' }
    }
}

Write-Host ''
Write-Host '  NetGuard scheduled jobs' -ForegroundColor Cyan
Write-Host "  platform : $($stack.platform) (provider '$($stack.provider)')" -ForegroundColor DarkGray
Write-Host "  root     : $NGRoot" -ForegroundColor DarkGray
Write-Host ''

if ($Remove) {
    $removed = Unregister-NGSchedule
    if ((Get-NGCount $removed) -gt 0) {
        foreach ($r in $removed) { Write-Host "  removed $r" -ForegroundColor Yellow }
    }
    else { Write-Host '  no NetGuard jobs were registered' -ForegroundColor DarkGray }
    Write-Host ''
    return
}

# Refuse to install something that would fail silently on every run.
try { $null = Get-NGConfig }
catch {
    throw 'NetGuard is not configured yet. Run Setup-NetGuard.ps1 first, otherwise every job would run and be unable to alert.'
}
Repair-NGAcl | Out-Null

# The schedule, defined once and interpreted by the provider.
$jobs = @(
    [pscustomobject]@{
        Name = 'Sentinel'; Script = 'agents/Invoke-SentinelAgent.ps1'
        Schedule = 'interval'; IntervalMinutes = 15; OffsetMinutes = 2
        RunAs = 'SYSTEM'; Description = 'Fast host detections every 15 minutes'
    }
    [pscustomobject]@{
        Name = 'Discovery'; Script = 'agents/Invoke-DiscoveryAgent.ps1'
        Schedule = 'interval'; IntervalMinutes = 60; OffsetMinutes = 7
        RunAs = 'SYSTEM'; Description = 'LAN inventory and persistence drift, hourly'
    }
    [pscustomobject]@{
        Name = 'Hardening'; Script = 'agents/Invoke-HardeningAgent.ps1'
        # 03:15 rather than 03:00: everything else on the machine runs on the
        # hour, and a laptop briefly awake at 03:00 is contended.
        Schedule = 'daily'; At = '03:15'
        RunAs = 'SYSTEM'; Description = 'Daily posture audit and remediation script generation'
    }
    [pscustomobject]@{
        Name = 'WeeklyReport'; Script = 'agents/Invoke-WeeklyReport.ps1'
        Schedule = 'weekly'; DayOfWeek = 'Monday'; At = '08:00'
        RunAs = 'SYSTEM'; Description = 'Weekly HTML report, Discord summary and SMS digest'
    }
)
if (-not $NoWatcher) {
    $jobs += [pscustomobject]@{
        Name = 'DownloadWatcher'; Script = 'scan/Watch-Downloads.ps1'
        Schedule = 'logon'; RunAs = 'USER'; LongRunning = $true
        Description = "Scans new downloads (runs as $WatcherUser)"
    }
}

# Idempotent: clear any previous registration first.
Unregister-NGSchedule | Out-Null

$registered = Register-NGSchedule -Jobs $jobs -NGRoot $NGRoot -UserPrincipal $WatcherUser
foreach ($j in $jobs) {
    $ok = ($j.Name -in $registered)
    $mark = if ($ok) { '+' } else { '!' }
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("  {0} {1,-16} {2,-7} {3}" -f $mark, $j.Name, $j.RunAs, $j.Description) -ForegroundColor $color
}

Write-Host ''
if (Get-Command Get-NGScheduleStatus -ErrorAction SilentlyContinue) {
    Write-Host '  Current schedule:' -ForegroundColor Cyan
    foreach ($s in (Get-NGScheduleStatus)) {
        Write-Host ("    {0,-26} state={1,-10} next={2}" -f $s.name, $s.state, $s.nextRun) -ForegroundColor DarkGray
    }
}

Write-Host ''
Write-Host '  Kick off a first run now:' -ForegroundColor White
if ((Get-NGPlatform) -eq 'Windows') {
    Write-Host '    Start-ScheduledTask -TaskPath "\NetGuard\" -TaskName Hardening' -ForegroundColor Yellow
    Write-Host '    Start-ScheduledTask -TaskPath "\NetGuard\" -TaskName Sentinel' -ForegroundColor Yellow
}
else {
    Write-Host '    sudo systemctl start netguard-hardening.service' -ForegroundColor Yellow
    Write-Host '    sudo systemctl start netguard-sentinel.service' -ForegroundColor Yellow
    Write-Host '    journalctl -u netguard-sentinel -f' -ForegroundColor Yellow
}
Write-Host ''
Write-Host '  The first Sentinel and Discovery runs record baselines and deliberately' -ForegroundColor DarkGray
Write-Host '  do not alert on what already exists. Drift from then on is what pages you.' -ForegroundColor DarkGray
Write-Host ''
