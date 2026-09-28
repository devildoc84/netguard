<#
.SYNOPSIS
    Prints what the loaded provider actually returns, on any platform.

.DESCRIPTION
    A diagnostic, not a test. Test-NetGuard.ps1 asserts; this one shows you the
    values so you can see whether a collector is returning something sensible,
    something empty, or something wrong. Useful when porting to a new distro.

.EXAMPLE
    pwsh -File tests/Probe-Provider.ps1
#>
[CmdletBinding()]
param([switch]$Full)

$ErrorActionPreference = 'Continue'
$NGRoot = Split-Path -Parent $PSScriptRoot

Import-Module (Join-Path $NGRoot 'lib/NetGuard.Platform.psm1') -DisableNameChecking -Global -Force
$stack = Import-NGStack -Force

function Section { param($t) Write-Host ''; Write-Host "== $t" -ForegroundColor Cyan }

Section 'Platform'
Write-Host "  platform      : $(Get-NGPlatform)"
Write-Host "  provider      : $($stack.provider)"
Write-Host "  pwsh          : $($PSVersionTable.PSVersion)"
$info = Get-NGProviderInfo
Write-Host "  os            : $($info.osVersion)"
Write-Host "  capabilities  : $($info.capabilities -join ', ')"

Section 'Contract'
$c = Test-NGProviderContract
Write-Host "  complete      : $($c.complete)  ($($c.implemented)/$($c.requiredTotal))"
if ($c.missing) { Write-Host "  MISSING       : $($c.missing -join ', ')" -ForegroundColor Red }
if ($c.missingOptional) { Write-Host "  optional gaps : $($c.missingOptional -join ', ')" -ForegroundColor DarkGray }

Section 'Elevation'
Write-Host "  elevated      : $(Test-NGElevated)"

Section 'Normalised posture'
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Get-NGHostPosture
$sw.Stop()
Write-Host "  collected in  : $($sw.ElapsedMilliseconds) ms"
Write-Host "  host          : $($p.hostName)"
Write-Host "  os            : $($p.platform.name) $($p.platform.version) (kernel $($p.platform.kernel))"
Write-Host "  uptime days   : $($p.uptimeDays)"
Write-Host "  antivirus     : present=$($p.antivirus.present) product=$($p.antivirus.product) rtp=$($p.antivirus.realtimeEnabled) sigAge=$($p.antivirus.signatureAgeDays) readable=$($p.antivirus.readable)"
foreach ($fw in @($p.firewall)) {
    Write-Host "  firewall      : $($fw.profile) enabled=$($fw.enabled) inbound=$($fw.defaultInbound) logging=$($fw.logging)"
}
foreach ($de in @($p.diskEncryption)) {
    Write-Host "  disk          : $($de.mount) status=$($de.status) method=$($de.method) readable=$($de.readable)"
}
Write-Host "  secureBoot    : $($p.secureBoot)"
Write-Host "  patching      : daysSince=$($p.patching.daysSinceLastUpdate) auto=$($p.patching.autoUpdate) pendingSec=$($p.patching.pendingSecurity) readable=$($p.patching.readable)"
Write-Host "  logging       : cmdAudit=$($p.logging.commandAuditing) script=$($p.logging.scriptLogging) retention=$($p.logging.adequateRetention)"
Write-Host "  ssh           : enabled=$($p.remoteAccess.ssh.enabled) root=$($p.remoteAccess.ssh.rootLogin) passwordAuth=$($p.remoteAccess.ssh.passwordAuth) port=$($p.remoteAccess.ssh.port)"
Write-Host "  rdp           : enabled=$($p.remoteAccess.rdp.enabled) secure=$($p.remoteAccess.rdp.secure)"
Write-Host "  shares        : $(Get-NGCount $p.shares)"
Write-Host "  raw keys      : $(@($p.raw.Keys) -join ', ')"

Section 'Collectors'
$ports = Get-NGListeningPorts
Write-Host "  ports         : $(Get-NGCount $ports) total, $(Get-NGCount @($ports | Where-Object { $_.reachable })) reachable"
foreach ($grp in ($ports | Group-Object scope | Sort-Object Name)) {
    Write-Host "                  scope $($grp.Name): $($grp.Count)"
}
$autoruns = Get-NGAutoruns
Write-Host "  autoruns      : $(Get-NGCount $autoruns)"
foreach ($grp in ($autoruns | Group-Object type | Sort-Object Count -Descending)) {
    Write-Host "                  $($grp.Name): $($grp.Count)"
}
$accts = Get-NGLocalAccounts
Write-Host "  accounts      : $(Get-NGCount $accts.users) users, $(Get-NGCount $accts.adminMembers) admins"
$certs = Get-NGTrustedCertificates
Write-Host "  root certs    : $(Get-NGCount $certs)"
$hosts = Get-NGHostsFileEntries
Write-Host "  hosts entries : $(Get-NGCount $hosts)"
$subnet = Get-NGLocalSubnet
if ($subnet) { Write-Host "  lan subnet    : $($subnet.Cidr) via $($subnet.Gateway) on $($subnet.Interface)" }
else { Write-Host "  lan subnet    : none detected" -ForegroundColor Yellow }

Section 'Events (20 min window)'
$ev = Get-NGSecurityEvents -SinceMinutes 20
foreach ($k in 'failedLogons', 'logCleared', 'accountChanges', 'newServices', 'avDetections', 'suspiciousExecution', 'remoteLogons') {
    Write-Host "  $($k.PadRight(20)): $(Get-NGCount $ev.$k)"
}

Section 'Antivirus scan of a known-good file'
$tmp = [IO.Path]::GetTempFileName()
Set-Content -LiteralPath $tmp -Value 'harmless test content'
$scan = Invoke-NGAntivirusScan -Path $tmp
Write-Host "  engine        : $($scan.engine)"
Write-Host "  ran           : $($scan.ran)"
Write-Host "  clean         : $($scan.clean)   (must be True or null - NEVER False for this file)"
Write-Host "  detail        : $($scan.detail)"
Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue

Section 'Detection'
$pf = Find-NGPostureFindings -Posture $p
Write-Host "  posture findings: $(Get-NGCount $pf)"
foreach ($x in ($pf | Sort-Object severityRank -Descending)) {
    Write-Host ("    [{0,-8}] {1,-16} {2}" -f $x.severity, $x.agent, $x.title)
}

Section 'Hardening catalogue'
$audit = Invoke-NGHardeningAudit
Write-Host "  score         : $($audit.score)/100"
Write-Host "  pass/fail/err : $($audit.passed)/$($audit.failed)/$($audit.errored)  of $(Get-NGCount $audit.checks) checks"
foreach ($chk in ($audit.checks | Sort-Object tier, @{e = 'state'; Descending = $true })) {
    $color = switch ($chk.state) { 'pass' { 'Green' } 'fail' { 'Yellow' } default { 'Red' } }
    Write-Host ("    T{0} {1,-6} {2,-20} {3}" -f $chk.tier, $chk.state, $chk.id, $chk.title) -ForegroundColor $color
    if ($chk.error) { Write-Host "         error: $($chk.error)" -ForegroundColor Red }
}

if ($Full) {
    Section 'Full posture JSON'
    $p | ConvertTo-Json -Depth 8
}

Write-Host ''
Write-Host "Probe complete on $(Get-NGPlatform) / provider '$($stack.provider)'." -ForegroundColor Cyan
Write-Host ''
