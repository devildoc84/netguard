<#
.SYNOPSIS
    NetGuard weekly report - rolls up the week, writes an HTML report, and sends
    a Discord summary plus a one-line SMS.

.DESCRIPTION
    Aggregates the findings ledger, hardening score history, scan verdicts and
    LAN inventory for the period, asks the AI layer for a prioritised narrative,
    and renders a self-contained HTML file (no external assets, so it opens
    correctly from disk or as an email attachment).

    If the AI layer is unavailable the report still generates with a deterministic
    summary. The report is the product; the narrative is an enhancement.

.PARAMETER Days
    Reporting window. Defaults to 7.

.PARAMETER OpenReport
    Open the finished HTML in the default browser.

.EXAMPLE
    .\Invoke-WeeklyReport.ps1 -Days 7 -OpenReport
#>
[CmdletBinding()]
param(
    [int]$Days = 7,
    [switch]$OpenReport,
    [switch]$NoAlert,
    [switch]$NoAI
)

. (Join-Path $PSScriptRoot '_Bootstrap.ps1')

$AGENT = 'weekly'
Write-NGLog "Building $Days-day report" -Agent $AGENT

$cfg = $null
try { $cfg = Get-NGConfig } catch { }

# ------------------------------------------------------------- gather ---------

$findings = @(Get-NGFindings -SinceDays $Days)
$bySeverity = [ordered]@{}
foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') {
    $bySeverity[$s] = (Get-NGCount @($findings | Where-Object { $_.severity -eq $s }))
}
$byCategory = @($findings | Group-Object category | Sort-Object Count -Descending |
    ForEach-Object { [pscustomobject]@{ category = $_.Name; count = $_.Count } })

$audit = Get-NGState -Name 'hardening-score' -Default $null
$posture = Get-NGState -Name 'posture' -Default $null
$perimeter = Get-NGState -Name 'perimeter' -Default $null
$lanDevices = @(Get-NGState -Name 'lan-last-seen' -Default @())
$aiSpend = Get-NGState -Name 'ai-spend' -Default $null

# Scan verdicts for the period, read back from the evidence directory.
$scanDir = Get-NGPath 'evidence'
$cutoff = (Get-Date).AddDays(-$Days)
$scans = @()
if (Test-Path $scanDir) {
    $scans = @(Get-ChildItem $scanDir -Filter 'scan-*.json' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $cutoff } | ForEach-Object {
            try { Get-Content $_.FullName -Raw -Encoding utf8 | ConvertFrom-Json } catch { }
        } | Where-Object { $null -ne $_ })
}
$scanSummary = [ordered]@{
    total       = (Get-NGCount $scans)
    quarantined = (Get-NGCount @($scans | Where-Object { $_.verdict -eq 'quarantine' }))
    suspicious  = (Get-NGCount @($scans | Where-Object { $_.verdict -eq 'suspicious' }))
    allowed     = (Get-NGCount @($scans | Where-Object { $_.verdict -eq 'allow' }))
}

# Agent liveness: a report that does not say which collectors ran is misleading,
# because zero findings from a dead agent looks the same as a clean week.
$heartbeat = Get-NGState -Name 'heartbeat' -Default $null
$agentStatus = @()
foreach ($a in 'sentinel', 'discovery', 'hardening', 'scan') {
    $last = $null; $ageH = $null
    if ($heartbeat -and $heartbeat.PSObject.Properties[$a]) {
        $t = [datetime]::MinValue
        if ([datetime]::TryParse($heartbeat.$a, [ref]$t)) {
            $last = $t.ToUniversalTime()
            $ageH = [math]::Round(((Get-Date).ToUniversalTime() - $last).TotalHours, 1)
        }
    }
    $agentStatus += [pscustomobject]@{
        agent = $a
        lastRun = if ($last) { $last.ToString('yyyy-MM-dd HH:mm') + 'Z' } else { 'never' }
        ageHours = $ageH
        healthy = ($null -ne $ageH -and $ageH -lt 26)
    }
}

$topFindings = @($findings | Sort-Object -Property @{Expression='severityRank';Descending=$true}, @{Expression='ts';Descending=$true} | Select-Object -First 25)

# ------------------------------------------------------------- narrative ------

$narrative = $null
if (-not $NoAI -and $cfg -and $cfg.ai.enabled) {
    Write-NGLog 'Requesting AI narrative' -Agent $AGENT
    $telemetry = [ordered]@{
        periodDays      = $Days
        host            = $(Get-NGHostName)
        findingsBySeverity = $bySeverity
        findingsByCategory = $byCategory
        hardeningScore  = if ($audit) { $audit.score } else { $null }
        failedControls  = if ($audit) { @($audit.checks | Where-Object { $_.state -eq 'fail' } |
                Select-Object id, tier, title, weight) } else { @() }
        scanSummary     = $scanSummary
        lanDeviceCount  = (Get-NGCount $lanDevices)
        perimeter       = $perimeter
        agentHealth     = $agentStatus
        notableFindings = @($topFindings | Select-Object severity, category, title, detail)
        defenderState   = if ($posture) { $posture.defender } else { $null }
    }
    $narrative = Invoke-NGWeeklyNarrative -Telemetry $telemetry -Model $(if ($cfg.ai.reportModel) { $cfg.ai.reportModel } else { 'opus' })
    if (-not $narrative) { Write-NGLog 'AI narrative unavailable; falling back to the deterministic summary.' -Level WARN -Agent $AGENT }
}

# ------------------------------------------------------------- render ---------

function HtmlEnc { param([AllowNull()]$s) if ($null -eq $s) { return '' } [System.Web.HttpUtility]::HtmlEncode([string]$s) }
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
if (-not ('System.Web.HttpUtility' -as [type])) {
    function HtmlEnc { param([AllowNull()]$s)
        if ($null -eq $s) { return '' }
        ([string]$s).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
    }
}

$sevColor = @{ Critical = '#dc2626'; High = '#ea580c'; Medium = '#d97706'; Low = '#2563eb'; Info = '#6b7280' }
$score = if ($audit) { [double]$audit.score } else { 0 }
$scoreColor = if ($score -ge 80) { '#16a34a' } elseif ($score -ge 60) { '#d97706' } else { '#dc2626' }

$html = New-Object System.Text.StringBuilder
[void]$html.AppendLine(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetGuard Weekly Report - $(HtmlEnc (Get-NGHostName))</title>
<style>
  :root {
    --bg:#ffffff; --fg:#111827; --muted:#6b7280; --card:#f9fafb; --border:#e5e7eb;
    --accent:#2563eb; --mono:ui-monospace,'Cascadia Code',Consolas,monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg:#0f1115; --fg:#e5e7eb; --muted:#9ca3af; --card:#171a21; --border:#2b303b; --accent:#60a5fa;
    }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; }
  .wrap { max-width:1000px; margin:0 auto; padding:32px 16px 64px; }
  header { border-bottom:2px solid var(--border); padding-bottom:20px; margin-bottom:28px; }
  h1 { margin:0 0 6px; font-size:26px; letter-spacing:-0.02em; }
  h2 { font-size:18px; margin:34px 0 12px; padding-bottom:6px; border-bottom:1px solid var(--border); }
  h3 { font-size:15px; margin:20px 0 8px; }
  .sub { color:var(--muted); font-size:13px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:20px 0; }
  .tile { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:14px 16px; }
  .tile .n { font-size:26px; font-weight:650; line-height:1.15; }
  .tile .l { font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin-top:2px; }
  table { width:100%; border-collapse:collapse; margin:12px 0; font-size:13.5px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); vertical-align:top; }
  th { font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); font-weight:600; }
  .pill { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11px;
          font-weight:650; color:#fff; white-space:nowrap; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:16px 18px; margin:14px 0; }
  .risk { border-left:3px solid var(--accent); padding-left:14px; margin:14px 0; }
  .risk .t { font-weight:650; }
  .risk .w { color:var(--muted); font-size:13.5px; margin:3px 0; }
  .risk .a { font-size:13.5px; }
  code { font-family:var(--mono); font-size:12.5px; background:var(--card);
         border:1px solid var(--border); border-radius:4px; padding:1px 5px; }
  ol,ul { padding-left:22px; }
  li { margin:5px 0; }
  .ok { color:#16a34a; } .bad { color:#dc2626; }
  footer { margin-top:44px; padding-top:16px; border-top:1px solid var(--border);
           color:var(--muted); font-size:12px; }
  @media (max-width:560px) { .wrap { padding:20px 16px 48px; } h1 { font-size:21px; } }
</style></head><body><div class="wrap">
<header>
  <h1>NetGuard Weekly Report</h1>
  <div class="sub">$(HtmlEnc (Get-NGHostName)) &middot; $((Get-Date).AddDays(-$Days).ToString('d MMM yyyy')) to $((Get-Date).ToString('d MMM yyyy')) &middot; generated $((Get-Date).ToString('yyyy-MM-dd HH:mm'))</div>
</header>
"@)

if ($narrative -and $narrative.headline) {
    [void]$html.AppendLine("<div class=""card""><h3 style=""margin-top:0"">$(HtmlEnc $narrative.headline)</h3>")
    foreach ($para in (($narrative.executiveSummary -split "`n`n"))) {
        if ($para.Trim()) { [void]$html.AppendLine("<p>$(HtmlEnc $para.Trim())</p>") }
    }
    [void]$html.AppendLine('</div>')
}

# --- tiles
[void]$html.AppendLine('<div class="grid">')
[void]$html.AppendLine("<div class=""tile""><div class=""n"" style=""color:$scoreColor"">$score</div><div class=""l"">Hardening score /100</div></div>")
foreach ($s in 'Critical', 'High', 'Medium') {
    $c = $bySeverity[$s]
    $col = if ($c -gt 0) { $sevColor[$s] } else { 'var(--muted)' }
    [void]$html.AppendLine("<div class=""tile""><div class=""n"" style=""color:$col"">$c</div><div class=""l"">$s findings</div></div>")
}
[void]$html.AppendLine("<div class=""tile""><div class=""n"">$(Get-NGCount $lanDevices)</div><div class=""l"">LAN devices</div></div>")
[void]$html.AppendLine("<div class=""tile""><div class=""n"">$($scanSummary.total)</div><div class=""l"">Files scanned</div></div>")
[void]$html.AppendLine('</div>')

# --- agent health
[void]$html.AppendLine('<h2>Agent health</h2>')
[void]$html.AppendLine('<p class="sub">An agent that stops running produces silence, and silence is not the same as a clean week. This table is how you tell them apart.</p>')
[void]$html.AppendLine('<table><tr><th>Agent</th><th>Last run</th><th>Age</th><th>Status</th></tr>')
foreach ($a in $agentStatus) {
    $st = if ($a.healthy) { '<span class="ok">healthy</span>' } elseif ($a.lastRun -eq 'never') { '<span class="sub">never run</span>' } else { '<span class="bad">STALE</span>' }
    $age = if ($null -ne $a.ageHours) { "$($a.ageHours) h" } else { '-' }
    [void]$html.AppendLine("<tr><td><code>$(HtmlEnc $a.agent)</code></td><td>$(HtmlEnc $a.lastRun)</td><td>$age</td><td>$st</td></tr>")
}
[void]$html.AppendLine('</table>')

# --- top risks from the narrative
if ($narrative -and (Get-NGCount $narrative.topRisks) -gt 0) {
    [void]$html.AppendLine('<h2>Top risks this week</h2>')
    foreach ($r in @($narrative.topRisks)) {
        [void]$html.AppendLine("<div class=""risk""><div class=""t"">$(HtmlEnc $r.risk)</div>")
        [void]$html.AppendLine("<div class=""w"">$(HtmlEnc $r.why)</div>")
        [void]$html.AppendLine("<div class=""a""><strong>Do:</strong> $(HtmlEnc $r.action)</div></div>")
    }
}

if ($narrative -and (Get-NGCount $narrative.recommendedActions) -gt 0) {
    [void]$html.AppendLine('<h2>Recommended actions, in priority order</h2><ol>')
    foreach ($a in @($narrative.recommendedActions)) { [void]$html.AppendLine("<li>$(HtmlEnc $a)</li>") }
    [void]$html.AppendLine('</ol>')
}

# --- hardening detail
if ($audit) {
    [void]$html.AppendLine('<h2>Hardening controls</h2>')
    if ($narrative -and $narrative.weekOverWeek) {
        [void]$html.AppendLine("<p>$(HtmlEnc $narrative.weekOverWeek)</p>")
    }
    [void]$html.AppendLine("<p class=""sub"">$($audit.passed) passing, $($audit.failed) failing, $($audit.errored) could not be evaluated. Run <code>harden\Apply-Tier1.ps1</code> elevated to close the safe ones.</p>")
    [void]$html.AppendLine('<table><tr><th>Tier</th><th>Control</th><th>Category</th><th>Weight</th><th>State</th></tr>')
    foreach ($c in @($audit.checks | Sort-Object @{e = 'state'; Descending = $false }, tier, @{e = 'weight'; Descending = $true })) {
        $st = switch ($c.state) {
            'pass' { '<span class="ok">pass</span>' }
            'fail' { '<span class="bad">fail</span>' }
            default { '<span class="sub">' + (HtmlEnc $c.state) + '</span>' }
        }
        [void]$html.AppendLine("<tr><td>$($c.tier)</td><td>$(HtmlEnc $c.title)<br><code>$(HtmlEnc $c.id)</code></td><td>$(HtmlEnc $c.category)</td><td>$($c.weight)</td><td>$st</td></tr>")
    }
    [void]$html.AppendLine('</table>')
}

# --- findings
[void]$html.AppendLine('<h2>Findings</h2>')
if ((Get-NGCount $findings) -eq 0) {
    [void]$html.AppendLine('<p>No findings recorded in this period.</p>')
}
else {
    [void]$html.AppendLine('<table><tr><th>When</th><th>Sev</th><th>Category</th><th>Finding</th></tr>')
    foreach ($f in $topFindings) {
        $col = $sevColor[[string]$f.severity]
        $when = ([string]$f.ts) -replace 'T', ' ' -replace 'Z', ''
        [void]$html.AppendLine("<tr><td class=""sub"">$(HtmlEnc $when)</td><td><span class=""pill"" style=""background:$col"">$(HtmlEnc $f.severity)</span></td><td>$(HtmlEnc $f.category)</td><td>$(HtmlEnc $f.title)</td></tr>")
    }
    [void]$html.AppendLine('</table>')
    if ((Get-NGCount $findings) -gt 25) {
        [void]$html.AppendLine("<p class=""sub"">Showing the 25 most severe of $(Get-NGCount $findings). The full ledger is in <code>state\findings.jsonl</code>.</p>")
    }
}

# --- downloads
[void]$html.AppendLine('<h2>Downloads scanned</h2>')
[void]$html.AppendLine("<p class=""sub"">$($scanSummary.total) file(s) analysed: $($scanSummary.allowed) allowed, $($scanSummary.suspicious) suspicious, $($scanSummary.quarantined) quarantined.</p>")
$notable = @($scans | Where-Object { $_.verdict -ne 'allow' } | Sort-Object { [int]$_.score } -Descending | Select-Object -First 12)
if ((Get-NGCount $notable) -gt 0) {
    [void]$html.AppendLine('<table><tr><th>File</th><th>Verdict</th><th>Score</th><th>Origin</th></tr>')
    foreach ($s in $notable) {
        $org = if ($s.motw.hostUrl) { $s.motw.hostUrl } elseif ($s.motw.referrerUrl) { $s.motw.referrerUrl } else { 'unknown' }
        if ($org.Length -gt 60) { $org = $org.Substring(0, 57) + '...' }
        $vc = if ($s.verdict -eq 'quarantine') { '#dc2626' } else { '#ea580c' }
        [void]$html.AppendLine("<tr><td>$(HtmlEnc $s.name)</td><td><span class=""pill"" style=""background:$vc"">$(HtmlEnc $s.verdict)</span></td><td>$($s.score)</td><td class=""sub"">$(HtmlEnc $org)</td></tr>")
    }
    [void]$html.AppendLine('</table>')
}

# --- LAN inventory
if ((Get-NGCount $lanDevices) -gt 0) {
    [void]$html.AppendLine('<h2>Network inventory</h2>')
    if ($perimeter) {
        $upnp = if ($perimeter.upnpIgdFound) { '<span class="bad">enabled</span>' } else { '<span class="ok">not detected</span>' }
        [void]$html.AppendLine("<p class=""sub"">External IP <code>$(HtmlEnc $perimeter.externalIp)</code> &middot; LAN <code>$(HtmlEnc $perimeter.lanCidr)</code> &middot; gateway <code>$(HtmlEnc $perimeter.gateway)</code> &middot; router UPnP: $upnp</p>")
    }
    [void]$html.AppendLine('<table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th></tr>')
    foreach ($d in @($lanDevices | Sort-Object ipAddress)) {
        $gw = if ($d.isGateway) { ' <span class="sub">(gateway)</span>' } else { '' }
        [void]$html.AppendLine("<tr><td><code>$(HtmlEnc $d.ipAddress)</code>$gw</td><td><code>$(HtmlEnc $d.mac)</code></td><td>$(HtmlEnc $(if ($d.hostName) { $d.hostName } else { '-' }))</td><td>$(HtmlEnc $d.vendor)</td></tr>")
    }
    [void]$html.AppendLine('</table>')
}

if ($narrative -and $narrative.noiseAssessment) {
    [void]$html.AppendLine('<h2>Detection tuning</h2>')
    [void]$html.AppendLine("<div class=""card"">$(HtmlEnc $narrative.noiseAssessment)</div>")
}
if ($narrative -and $narrative.whatImprovedThisWeek) {
    [void]$html.AppendLine('<h2>What improved</h2>')
    [void]$html.AppendLine("<p>$(HtmlEnc $narrative.whatImprovedThisWeek)</p>")
}

$spendNote = ''
if ($aiSpend) { $spendNote = " &middot; AI spend this month: `$$($aiSpend.usd) over $($aiSpend.calls) call(s)" }
[void]$html.AppendLine(@"
<footer>
  Generated by NetGuard on $(HtmlEnc (Get-NGHostName)) at $((Get-Date).ToString('u'))$spendNote.<br>
  Detections are rule-based; the AI layer explains and prioritises but never decides whether to alert.
  Hardening scripts are generated for review and are never applied automatically.
</footer>
</div></body></html>
"@)

$reportDir = Get-NGPath 'reports'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
$reportPath = Join-Path $reportDir ("netguard-report-{0}.html" -f (Get-Date -Format 'yyyy-MM-dd'))
Set-Content -LiteralPath $reportPath -Value $html.ToString() -Encoding utf8
Write-NGLog "Report written to $reportPath" -Agent $AGENT

# Stable "latest" path so a bookmark or a scheduled email always finds it.
Copy-Item -LiteralPath $reportPath -Destination (Join-Path $reportDir 'netguard-latest.html') -Force -ErrorAction SilentlyContinue

# ------------------------------------------------------------- notify ---------

if (-not $NoAlert) {
    $headline = if ($narrative -and $narrative.headline) { $narrative.headline } else {
        "Weekly summary: score $score/100, $($bySeverity['Critical'] + $bySeverity['High']) high-or-critical findings."
    }
    $fields = [ordered]@{
        'Hardening score' = "$score/100"
        'Critical / High' = "$($bySeverity['Critical']) / $($bySeverity['High'])"
        'Medium / Low'    = "$($bySeverity['Medium']) / $($bySeverity['Low'])"
        'Files scanned'   = "$($scanSummary.total) ($($scanSummary.quarantined) quarantined)"
        'LAN devices'     = (Get-NGCount $lanDevices)
        'Report'          = $reportPath
    }
    $stale = @($agentStatus | Where-Object { -not $_.healthy -and $_.lastRun -ne 'never' })
    if ((Get-NGCount $stale) -gt 0) {
        $fields['WARNING'] = "Stale agents: " + (($stale | ForEach-Object { $_.agent }) -join ', ')
    }

    $desc = $headline
    if ($narrative -and (Get-NGCount $narrative.recommendedActions) -gt 0) {
        $desc += "`n`n**Do these first:**`n" + ((@($narrative.recommendedActions) | Select-Object -First 5 |
                ForEach-Object { "- $_" }) -join "`n")
    }
    $sev = if ($bySeverity['Critical'] -gt 0) { 'High' } elseif ($score -lt 60) { 'Medium' } else { 'Info' }
    Send-NGDiscord -Title "NetGuard weekly report - $(Get-NGHostName)" -Description $desc `
        -Severity $sev -Fields $fields -Footer "Report: $reportPath" | Out-Null

    Send-NGSms -Body ("NG weekly: score {0}/100, {1} crit, {2} high, {3} quarantined. See Discord/report." -f `
            $score, $bySeverity['Critical'], $bySeverity['High'], $scanSummary.quarantined) | Out-Null
}

Send-NGHeartbeat -Agent $AGENT
Set-NGState -Name 'lastrun-weekly' -Value ([pscustomobject]@{
        at = (Get-Date).ToUniversalTime().ToString('o'); report = $reportPath })

if ($OpenReport) { Start-Process $reportPath }
Write-Host ""
Write-Host "Report: $reportPath" -ForegroundColor Cyan
exit 0
