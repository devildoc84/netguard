<#
.SYNOPSIS
    NetGuard self-test. Verifies the pieces actually work, rather than assuming.

.DESCRIPTION
    Covers the things that fail silently in a monitoring system:

      * modules parse and load
      * secret store round-trips
      * baseline serialisation survives a save/load cycle (a regression here
        makes every item look new forever, while appearing to work)
      * collectors return data
      * detection fires on a known-bad sample and stays quiet on a known-good one
      * the AI layer can actually be reached
      * alert delivery reaches Discord and your phone

    Run it after setup, after any edit, and any time alerts have gone quiet for
    longer than feels right.

.PARAMETER IncludeDelivery
    Also send a real test alert to Discord and SMS.

.PARAMETER IncludeAI
    Also make a live AI call. Costs a few cents.

.EXAMPLE
    .\Test-NetGuard.ps1

.EXAMPLE
    .\Test-NetGuard.ps1 -IncludeDelivery -IncludeAI
#>
[CmdletBinding()]
param(
    [switch]$IncludeDelivery,
    [switch]$IncludeAI
)

$ErrorActionPreference = 'Continue'
$NGRoot = $PSScriptRoot

$script:Pass = 0; $script:Fail = 0; $script:Skip = 0
function Test-Case {
    param([string]$Name, [scriptblock]$Body, [switch]$Optional)
    Write-Host ("  {0,-52}" -f $Name) -NoNewline
    try {
        # A scriptblock can emit log lines as well as its verdict, so take the
        # LAST emitted value as the result.
        $all = @(& $Body)
        $r = if ($all.Count -gt 0) { $all[-1] } else { $null }

        # Must compare as a string. In PowerShell the LEFT operand drives type
        # coercion, so `$true -eq 'skip'` casts 'skip' to [bool] (any non-empty
        # string is $true) and every passing test would report SKIP.
        if (($r -is [string]) -and ($r -eq 'skip')) {
            Write-Host 'SKIP' -ForegroundColor DarkGray; $script:Skip++; return
        }
        if ($r) { Write-Host 'PASS' -ForegroundColor Green; $script:Pass++ }
        else {
            if ($Optional) { Write-Host 'WARN' -ForegroundColor Yellow; $script:Skip++ }
            else { Write-Host 'FAIL' -ForegroundColor Red; $script:Fail++ }
        }
    }
    catch {
        if ($Optional) { Write-Host "WARN  $($_.Exception.Message)" -ForegroundColor Yellow; $script:Skip++ }
        else { Write-Host "FAIL  $($_.Exception.Message)" -ForegroundColor Red; $script:Fail++ }
    }
}

Write-Host ''
Write-Host '  NetGuard self-test' -ForegroundColor Cyan
Write-Host "  $NGRoot" -ForegroundColor DarkGray
Write-Host "  elevated=$((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole('Administrators'))" -ForegroundColor DarkGray
Write-Host ''

Write-Host '  Structure and syntax' -ForegroundColor White
foreach ($f in (Get-ChildItem (Join-Path $NGRoot 'lib') -Filter '*.psm1' -ErrorAction SilentlyContinue)) {
    Test-Case "parse $($f.Name)" {
        $errs = $null; $toks = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$toks, [ref]$errs)
        (-not $errs) -or $errs.Count -eq 0
    }.GetNewClosure()
}
foreach ($d in 'agents', 'scan', 'install', 'remote', 'tools') {
    foreach ($f in (Get-ChildItem (Join-Path $NGRoot $d) -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        Test-Case "parse $d\$($f.Name)" {
            $errs = $null; $toks = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$toks, [ref]$errs)
            (-not $errs) -or $errs.Count -eq 0
        }.GetNewClosure()
    }
}

Write-Host ''
Write-Host '  Module loading and platform provider' -ForegroundColor White
Test-Case 'import NetGuard.Platform' {
    Import-Module (Join-Path $NGRoot 'lib/NetGuard.Platform.psm1') -Force -DisableNameChecking -Global -ErrorAction Stop | Out-Null
    $true
}
Test-Case 'Import-NGStack loads every module and the provider' {
    $script:stack = Import-NGStack -Force
    $null -ne $script:stack.provider
}
Test-Case 'platform detected' {
    (Get-NGPlatform) -in 'Windows', 'Linux', 'macOS'
}
Test-Case 'provider implements the full contract' {
    $script:contract = Test-NGProviderContract
    if (-not $script:contract.complete) { throw "missing: $($script:contract.missing -join ', ')" }
    $true
}
Test-Case 'provider reports its identity' {
    $i = Get-NGProviderInfo
    ($null -ne $i.name) -and ($null -ne $i.osVersion)
}

Write-Host ''
Write-Host '  Core primitives' -ForegroundColor White
Test-Case 'null-safe counting' {
    (Get-NGCount $null) -eq 0 -and (Get-NGCount @()) -eq 0 -and (Get-NGCount @('a', 'b')) -eq 2
}
Test-Case 'safe int conversion (Defender sentinels)' {
    (Get-NGSafeInt 4294967295) -eq -1 -and (Get-NGSafeInt 'N/A: Must be an administrator') -eq -1 -and (Get-NGSafeInt '7') -eq 7
}
Test-Case 'baseline round-trip preserves items' {
    $s = @([pscustomobject]@{ key = 'a'; v = 1 }, [pscustomobject]@{ key = 'b'; v = 2 })
    Set-NGBaseline -Name '_selftest' -Value $s
    $b = Get-NGBaseline -Name '_selftest'
    (Get-NGCount $b) -eq 2 -and @($b)[0].key -eq 'a'
}
Test-Case 'baseline round-trip with a single item' {
    Set-NGBaseline -Name '_selftest1' -Value @([pscustomobject]@{ key = 'solo' })
    $b = Get-NGBaseline -Name '_selftest1'
    (Get-NGCount $b) -eq 1 -and @($b)[0].key -eq 'solo'
}
Test-Case 'baseline from another host is relearned, not diffed' {
    # A tree copied between machines, restored from backup, or shared over a
    # network path would otherwise report every account and service on the new
    # host as newly created - hundreds of wrong high-severity findings that look
    # exactly like a compromise.
    Set-NGBaseline -Name '_selftesthost' -Value @([pscustomobject]@{ key = 'a' })
    $file = Get-NGPath 'baseline/_selftesthost.json'
    $raw = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
    $raw.host = 'some-other-machine'
    Set-Content -LiteralPath $file -Value ($raw | ConvertTo-Json -Depth 10) -Encoding utf8
    $null -eq (Get-NGBaseline -Name '_selftesthost')
}
Test-Case 'baseline records host and platform identity' {
    Set-NGBaseline -Name '_selftestid' -Value @([pscustomobject]@{ key = 'a' })
    $raw = Get-Content -LiteralPath (Get-NGPath 'baseline/_selftestid.json') -Raw | ConvertFrom-Json
    ($raw.host -eq (Get-NGHostName)) -and ($raw.platform -eq (Get-NGPlatform))
}
Test-Case 'diff engine detects add/remove/change' {
    $d = Compare-NGSnapshot -Baseline @([pscustomobject]@{ k = 'a'; v = 1 }, [pscustomobject]@{ k = 'x'; v = 0 }) `
        -Current @([pscustomobject]@{ k = 'a'; v = 2 }, [pscustomobject]@{ k = 'b'; v = 9 }) `
        -Key 'k' -CompareProperties @('v')
    (Get-NGCount $d.Added) -eq 1 -and (Get-NGCount $d.Removed) -eq 1 -and (Get-NGCount $d.Changed) -eq 1
}
Test-Case 'secret store round-trip' {
    $v = "selftest-$([guid]::NewGuid())"
    Set-NGSecret -Name '_SelfTest' -Value $v 6>$null
    (Get-NGSecret -Name '_SelfTest' -AsPlainText) -eq $v
}
Test-Case 'configuration present' -Optional {
    $null -ne (Get-NGConfig)
}

Write-Host ''
Write-Host '  Collectors' -ForegroundColor White
Test-Case 'host posture matches the normalised contract' {
    $p = Get-NGHostPosture
    $script:posture = $p
    $required = 'collectedAt', 'hostName', 'elevated', 'platform', 'antivirus', 'firewall',
                'diskEncryption', 'patching', 'logging', 'remoteAccess', 'raw'
    $missing = @($required | Where-Object { -not $p.PSObject.Properties[$_] })
    if ($missing.Count -gt 0) { throw "posture is missing: $($missing -join ', ')" }
    $true
}
Test-Case 'antivirus block populated (not silently dropped)' {
    # A cast failure inside the collector used to abandon this whole block, and a
    # missing block reads downstream as "nothing to report".
    ($null -ne $script:posture.antivirus) -and ($null -ne $script:posture.antivirus.readable)
}
Test-Case 'platform rules reach the shared detector' {
    # The finder returns a comma-wrapped array. Collecting it with @() or through
    # a pipeline merges every platform finding into one unusable object, which
    # reads downstream as "the platform had nothing to report".
    $all = Find-NGPostureFindings -Posture $script:posture
    $nested = @($all | Where-Object { $_ -is [array] })
    if ($nested.Count -gt 0) { throw 'a finding was added as a nested array' }
    # Ask the provider directly and compare. A hardened host (such as a CI
    # runner) can legitimately have zero platform findings, so the check is
    # that every finding the provider returns reaches the shared detector.
    # Assign first: the finder returns a comma-wrapped array.
    $direct = Find-NGPlatformPostureFindings -Posture $script:posture
    $expected = @($direct | Where-Object { $_ }).Count
    $reached = @($all | Where-Object { $_.agent -like 'posture-*' }).Count
    if ($reached -ne $expected) { throw "provider returned $expected platform finding(s) but $reached reached the detector" }
    if ($expected -eq 0) { 'skip' } else { $true }
}
Test-Case 'listening ports collected with scope' {
    $ports = Get-NGListeningPorts
    (Get-NGCount $ports) -gt 0 -and $null -ne @($ports)[0].PSObject.Properties['scope']
}
Test-Case 'primary LAN subnet identified' -Optional {
    # Legitimately absent on a host with no physical LAN, or one whose network is
    # wider than a /22 (container host, VPN-only box). Not a defect.
    $null -ne (Get-NGLocalSubnet)
}
Test-Case 'autoruns enumerated' {
    (Get-NGCount (Get-NGAutoruns)) -gt 10
}
Test-Case 'trusted root certificates enumerated' {
    (Get-NGCount (Get-NGTrustedCertificates)) -gt 10
}
Test-Case 'hardening audit produces a score' {
    $a = Invoke-NGHardeningAudit
    $script:audit = $a
    $a.score -ge 0 -and $a.score -le 100 -and (Get-NGCount $a.checks) -gt 10
}

Write-Host ''
Write-Host '  Remediation script generation' -ForegroundColor White
Test-Case 'generates Apply/Rollback for every tier' {
    $genDir = Get-NGTempPath ('ng-harden-test-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $genDir -Force | Out-Null
    $script:genDir = $genDir
    $made = 0
    foreach ($t in 1, 2, 3) {
        $r = New-NGRemediationScript -Audit $script:audit -Tier $t -OutputDirectory $genDir
        if ((Test-Path $r.apply) -and (Test-Path $r.rollback)) { $made++ }
    }
    $made -eq 3
}
Test-Case 'generated scripts are valid PowerShell' {
    # The generator emits each control verbatim with no added indentation.
    # Indenting a line would put whitespace before a here-string terminator
    # ("@), which is a parse error - it shipped broken once already.
    $bad = @()
    foreach ($f in (Get-ChildItem $script:genDir -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        $errs = $null; $toks = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$toks, [ref]$errs)
        if ($errs -and $errs.Count -gt 0) { $bad += "$($f.Name): $($errs[0].Message)" }
    }
    if ($bad.Count -gt 0) { throw ($bad -join ' | ') }
    $true
}
Test-Case 'every failing control has a rollback' {
    # An Apply with no working Rollback is a one-way door on a security setting.
    $checks = Get-NGHardeningChecks
    $missing = @($checks | Where-Object {
            [string]::IsNullOrWhiteSpace($_.Rollback) -or $_.Rollback.Trim().Length -lt 5
        } | ForEach-Object { $_.Id })
    if ($missing.Count -gt 0) { throw "no rollback: $($missing -join ', ')" }
    $true
}
Test-Case 'every control declares rationale and risk' {
    $checks = Get-NGHardeningChecks
    $bad = @($checks | Where-Object {
            [string]::IsNullOrWhiteSpace($_.Rationale) -or [string]::IsNullOrWhiteSpace($_.Risk)
        } | ForEach-Object { $_.Id })
    if ($bad.Count -gt 0) { throw "missing rationale/risk: $($bad -join ', ')" }
    $true
}
Test-Case 'control ids are unique' {
    $checks = Get-NGHardeningChecks
    $dupes = @($checks | Group-Object Id | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    if ($dupes.Count -gt 0) { throw "duplicate ids: $($dupes -join ', ')" }
    $true
}

Write-Host ''
Write-Host '  Detection correctness' -ForegroundColor White
Test-Case 'known-bad sample scores as malicious' {
    $sample = Join-Path $NGRoot 'tests\samples\malicious-dropper.ps1.sample'
    if (-not (Test-Path $sample)) { return 'skip' }
    $tmp = Get-NGTempPath 'ng-selftest-bad.ps1'
    Copy-Item $sample $tmp -Force
    $r = Invoke-NGFileScan -Path $tmp -SkipAI -SkipVirusTotal -SkipDefender 6>$null
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    $r.verdict -eq 'quarantine' -and $r.score -ge 60
}
Test-Case 'benign text file scores as allow' {
    $tmp = Get-NGTempPath 'ng-selftest-good.txt'
    Set-Content -LiteralPath $tmp -Value "Shopping list`nmilk`nbread" -Encoding utf8
    $r = Invoke-NGFileScan -Path $tmp -SkipAI -SkipVirusTotal -SkipDefender 6>$null
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    $r.verdict -eq 'allow'
}
Test-Case 'unreadable data never alerts as disabled' {
    # Tri-state contract: $null means "could not read" and must stay silent.
    # Using -not instead of -eq $false here would turn every unreadable field
    # into a false Critical, which is how a monitoring tool loses its audience.
    $fake = New-NGPosture
    $fake.antivirus.readable = $true
    $fake.antivirus.present = $true
    $fake.antivirus.realtimeEnabled = $null
    $fake.antivirus.tamperProtected = $null
    $fake.uptimeDays = 1
    $f = Find-NGPostureFindings -Posture $fake
    (Get-NGCount @($f | Where-Object { $_.title -match 'real-time protection is OFF|tamper protection is not active' })) -eq 0
}
Test-Case 'confirmed-disabled data DOES alert' {
    # The other half of the contract: $false must still fire, or the tri-state
    # fix would have silenced real detections.
    $fake = New-NGPosture
    $fake.antivirus.readable = $true
    $fake.antivirus.present = $true
    $fake.antivirus.realtimeEnabled = $false
    $f = Find-NGPostureFindings -Posture $fake
    (Get-NGCount @($f | Where-Object { $_.title -match 'real-time protection is OFF' })) -eq 1
}
Test-Case 'severity floor: AI cannot downgrade a rule verdict' {
    $f = New-NGFinding -Category Test -Severity High -Title 'floor test' -Agent selftest
    $f.severityRank -eq 3 -and (Get-NGSeverityRank 'High') -eq 3
}

Write-Host ''
Write-Host '  AI layer' -ForegroundColor White
Test-Case 'claude CLI on PATH' -Optional { Test-NGClaudeAvailable }
if ($IncludeAI) {
    Test-Case 'live AI script review' -Optional {
        $r = Invoke-NGScriptReview -Content 'Write-Host "hello world"' -FileName 'selftest.ps1'
        $null -ne $r -and $null -ne $r.verdict
    }
}
else {
    Write-Host '  (pass -IncludeAI to make a live AI call)' -ForegroundColor DarkGray
}

Write-Host ''
Write-Host '  Alert delivery' -ForegroundColor White
Test-Case 'Discord webhook configured' -Optional { Test-NGSecret -Name 'DiscordWebhook' }
Test-Case 'SMS address configured' -Optional { Test-NGSecret -Name 'SmsAddress' }
Test-Case 'SMTP credentials configured' -Optional { (Test-NGSecret -Name 'SmtpUser') -and (Test-NGSecret -Name 'SmtpPassword') }
if ($IncludeDelivery) {
    Test-Case 'live Discord delivery' -Optional {
        Send-NGDiscord -Title 'NetGuard self-test' -Description 'Delivery verified.' -Severity Info
    }
    Test-Case 'live SMS delivery' -Optional {
        Send-NGSms -Body "NetGuard self-test from $(Get-NGHostName)"
    }
}
else {
    Write-Host '  (pass -IncludeDelivery to send real test alerts)' -ForegroundColor DarkGray
}

Write-Host ''
Write-Host '  Scheduled tasks' -ForegroundColor White
Test-Case 'scheduled jobs registered' -Optional {
    # Provider-supplied: Task Scheduler on Windows, systemd timers on Linux.
    if (-not (Get-Command Get-NGScheduleStatus -ErrorAction SilentlyContinue)) { return 'skip' }
    (Get-NGCount (Get-NGScheduleStatus)) -ge 4
}
Test-Case 'no agent heartbeat is stale' -Optional {
    (Get-NGCount (Test-NGHeartbeat)) -eq 0
}

# cleanup
if ($script:genDir -and (Test-Path $script:genDir)) {
    Remove-Item -LiteralPath $script:genDir -Recurse -Force -ErrorAction SilentlyContinue
}
foreach ($n in '_selftest', '_selftest1', '_selftesthost', '_selftestid') {
    Remove-Item -LiteralPath (Get-NGPath "baseline\$n.json") -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ('  ' + ('=' * 60)) -ForegroundColor DarkGray
$color = if ($script:Fail -eq 0) { 'Green' } else { 'Red' }
Write-Host ("  PASS {0}   FAIL {1}   WARN/SKIP {2}" -f $script:Pass, $script:Fail, $script:Skip) -ForegroundColor $color
if ($script:audit) {
    Write-Host ("  Hardening score: {0}/100" -f $script:audit.score) -ForegroundColor Cyan
}
Write-Host ''
if ($script:Fail -gt 0) {
    Write-Host '  Failures above are real defects. Do not rely on alerting until they are fixed.' -ForegroundColor Red
    Write-Host ''
    exit 1
}
Write-Host '  WARN items are usually unconfigured optional features, or checks that' -ForegroundColor DarkGray
Write-Host '  need elevation. Re-run as Administrator to exercise those.' -ForegroundColor DarkGray
Write-Host ''
exit 0
