<#
.SYNOPSIS
    Interactive first-run setup for NetGuard: configuration, secrets and a live
    delivery test.

.DESCRIPTION
    Every secret you enter here is read straight from this console into a DPAPI
    blob on this machine. Nothing is echoed, nothing is written to a transcript,
    and nothing is sent anywhere except the service it belongs to.

    Run this ELEVATED. Two things depend on it:
      * the secret store and entropy key get locked to SYSTEM + Administrators
      * the scheduled tasks that follow run as SYSTEM and must be able to read them

.EXAMPLE
    .\Setup-NetGuard.ps1

.EXAMPLE
    .\Setup-NetGuard.ps1 -Reconfigure
#>
[CmdletBinding()]
param(
    [switch]$Reconfigure,
    [switch]$SkipTest
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib/NetGuard.Platform.psm1') -DisableNameChecking -Global
$NGStack = Import-NGStack

function Write-Head { param($t) Write-Host ''; Write-Host "  $t" -ForegroundColor Cyan; Write-Host ('  ' + ('-' * ($t.Length))) -ForegroundColor DarkGray }
function Write-Note { param($t) Write-Host "  $t" -ForegroundColor DarkGray }
function Ask {
    param($Prompt, $Default)
    $suffix = if ($null -ne $Default -and "$Default" -ne '') { " [$Default]" } else { '' }
    $v = Read-Host "  $Prompt$suffix"
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    $v.Trim()
}
function AskSecret {
    param($Prompt)
    $ss = Read-Host "  $Prompt" -AsSecureString
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}
function AskYesNo {
    param($Prompt, [bool]$Default = $true)
    $d = if ($Default) { 'Y/n' } else { 'y/N' }
    $v = Read-Host "  $Prompt [$d]"
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    $v -match '^\s*[yY]'
}

Clear-Host
Write-Host ''
Write-Host '  NetGuard setup' -ForegroundColor White
Write-Host '  ==============' -ForegroundColor White
Write-Host ''
Write-Note "Install root: $(Get-NGRoot)"
Write-Note "Host: $(Get-NGHostName)   Platform: $($NGStack.platform) (provider $($NGStack.provider))"
Write-Note "Privileged: $(Test-NGElevated)"

if (-not (Test-NGElevated)) {
    Write-Host ''
    Write-Warning 'Not running with administrative privilege.'
    Write-Note 'Setup will continue, but the secret store keeps its default permissions'
    Write-Note 'and the scheduled jobs cannot be registered.'
    if ((Get-NGPlatform) -eq 'Windows') { Write-Note 'Re-run from an elevated PowerShell prompt to finish.' }
    else { Write-Note 'Re-run with: sudo pwsh -File ./Setup-NetGuard.ps1' }
    if (-not (AskYesNo 'Continue anyway?' $false)) { return }
}

Initialize-NGTree

# --------------------------------------------------------------- config ------

$existing = $null
if (-not $Reconfigure) {
    try { $existing = Get-NGConfig } catch { }
}
if ($existing) {
    Write-Host ''
    Write-Note 'An existing configuration was found. Press Enter at each prompt to keep the current value.'
}

Write-Head 'Discord (primary alert channel)'
Write-Note 'In Discord: Server Settings > Integrations > Webhooks > New Webhook > Copy Webhook URL.'
Write-Note 'Use a private channel - alerts describe weaknesses in your own machine.'
Write-Note 'The URL is a bearer credential: anyone holding it can post to that channel.'
Write-Host ''

$discordEnabled = AskYesNo 'Enable Discord alerts?' $true
if ($discordEnabled) {
    if ((Test-NGSecret -Name 'DiscordWebhook') -and -not $Reconfigure) {
        if (AskYesNo 'A Discord webhook is already stored. Replace it?' $false) {
            $hook = AskSecret 'Discord webhook URL (input hidden)'
            if ($hook) { Set-NGSecret -Name 'DiscordWebhook' -Value $hook }
        }
    }
    else {
        $hook = AskSecret 'Discord webhook URL (input hidden)'
        if ($hook -notmatch '^https://(discord|discordapp)\.com/api/webhooks/') {
            Write-Warning 'That does not look like a Discord webhook URL. Storing it anyway; the test below will tell you.'
        }
        if ($hook) { Set-NGSecret -Name 'DiscordWebhook' -Value $hook }
    }
}

Write-Head 'Phone alerts via email-to-SMS'
Write-Note 'Carrier gateways are free but lossy: they throttle, truncate at ~160 characters,'
Write-Note 'and several carriers are retiring them. NetGuard therefore sends only the most'
Write-Note 'severe alerts this way and keeps the full detail in Discord.'
Write-Host ''

$smsEnabled = AskYesNo 'Enable SMS alerts?' $true
$smtpHost = 'smtp.gmail.com'; $smtpPort = 587; $smtpSsl = $true
if ($smsEnabled) {
    Write-Host ''
    $i = 1
    $carriers = Get-NGCarrierGateway
    foreach ($k in $carriers.Keys) { Write-Host ("    {0,2}. {1,-20} @{2}" -f $i, $k, $carriers[$k]); $i++ }
    Write-Host ''
    $sel = Ask 'Carrier number (or type a full address like 5551234567@vtext.com)' ''
    $smsAddr = $null
    if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $carriers.Count) {
        $gw = @($carriers.Values)[[int]$sel - 1]
        $num = Ask 'Your 10-digit mobile number (digits only)' ''
        $num = ($num -replace '\D', '')
        if ($num.Length -ge 10) { $smsAddr = "$num@$gw" }
        else { Write-Warning 'That number did not look valid; skipping SMS address.' }
    }
    elseif ($sel -match '@') { $smsAddr = $sel }

    if ($smsAddr) {
        Write-Note "SMS will be delivered to: $smsAddr"
        Set-NGSecret -Name 'SmsAddress' -Value $smsAddr
    }

    Write-Host ''
    Write-Note 'SMTP account used to send. For Gmail you MUST use an App Password'
    Write-Note '(myaccount.google.com > Security > 2-Step Verification > App passwords),'
    Write-Note 'not your normal password. Prefer a dedicated sending account over your main one.'
    $smtpHost = Ask 'SMTP host' $(if ($existing) { $existing.notify.smtpHost } else { 'smtp.gmail.com' })
    $smtpPort = [int](Ask 'SMTP port' $(if ($existing) { $existing.notify.smtpPort } else { 587 }))
    $smtpSsl = AskYesNo 'Use TLS/SSL?' $true
    $smtpUser = Ask 'SMTP username (full email address)' $(Get-NGSecret -Name 'SmtpUser' -AsPlainText)
    if ($smtpUser) { Set-NGSecret -Name 'SmtpUser' -Value $smtpUser }
    if (-not (Test-NGSecret -Name 'SmtpPassword') -or (AskYesNo 'Set/replace the SMTP password?' (-not (Test-NGSecret -Name 'SmtpPassword')))) {
        $pw = AskSecret 'SMTP password / app password (input hidden)'
        if ($pw) { Set-NGSecret -Name 'SmtpPassword' -Value $pw }
    }
}

Write-Head 'AI analysis layer'
Write-Note 'The AI layer explains and prioritises findings and reviews downloaded script'
Write-Note 'source. It never decides whether to alert - rules do that - so NetGuard keeps'
Write-Note 'working with this disabled.'
Write-Host ''
$aiEnabled = AskYesNo 'Enable AI triage and reporting?' $true
if ($aiEnabled) {
    if (-not (Test-NGClaudeAvailable)) {
        Write-Warning 'The claude CLI was not found on PATH. AI features will no-op until it is installed.'
    }
    Write-Note 'Scheduled tasks run as SYSTEM, which has no interactive Claude login, so they'
    Write-Note 'need a long-lived token. Generate one by running this in your own shell:'
    Write-Host '      claude setup-token' -ForegroundColor Yellow
    Write-Note 'Then paste the token below. An sk-ant-... API key works too.'
    Write-Host ''
    if (-not (Test-NGSecret -Name 'ClaudeToken') -or (AskYesNo 'Set/replace the Claude token?' (-not (Test-NGSecret -Name 'ClaudeToken')))) {
        $tok = AskSecret 'Claude token (input hidden, press Enter to skip)'
        if ($tok) { Set-NGSecret -Name 'ClaudeToken' -Value $tok }
    }
}

Write-Head 'Download scanning'
if ((Get-NGPlatform) -ne 'Windows') {
    Write-Note 'On Linux the signature stage uses ClamAV when installed. Without it the'
    Write-Note 'pipeline still runs on static analysis and, optionally, VirusTotal.'
}
$downloads = Get-NGDownloadsPath
$watchPath = Ask 'Folder to watch for new downloads' $downloads
$autoQ = AskYesNo 'Automatically quarantine files that score as malicious?' $true
Write-Note 'Quarantine renames the file so it cannot execute and moves it to netguard\quarantine.'
Write-Note 'Nothing is ever deleted - the file is evidence of how it arrived.'
Write-Host ''
$vtEnabled = AskYesNo 'Enable VirusTotal hash lookups? (hash only, file contents are never uploaded)' $false
if ($vtEnabled) {
    Write-Note 'Free API key: virustotal.com > sign up > profile > API key. Free tier allows 4 lookups/minute.'
    if (-not (Test-NGSecret -Name 'VirusTotalApiKey') -or (AskYesNo 'Set/replace the VirusTotal key?' $true)) {
        $vt = AskSecret 'VirusTotal API key (input hidden)'
        if ($vt) { Set-NGSecret -Name 'VirusTotalApiKey' -Value $vt }
    }
}

Write-Head 'Alert routing'
Write-Note 'Severity floors decide what reaches you. Too low and you will mute the channel;'
Write-Note 'too high and you will miss things. The defaults are a reasonable starting point.'
Write-Host ''
$discordFloor = Ask 'Minimum severity for Discord (Info/Low/Medium/High/Critical)' $(if ($existing) { $existing.notify.discordMinSeverity } else { 'Medium' })
$smsFloor = Ask 'Minimum severity for SMS' $(if ($existing) { $existing.notify.smsMinSeverity } else { 'Critical' })

# --------------------------------------------------------------- save --------

$config = [ordered]@{
    version   = 1
    host      = $(Get-NGHostName)
    createdAt = (Get-Date).ToUniversalTime().ToString('o')
    notify    = [ordered]@{
        discordEnabled       = $discordEnabled
        discordMinSeverity   = $discordFloor
        discordHourlyCeiling = 12
        smsEnabled           = $smsEnabled
        smsMinSeverity       = $smsFloor
        smsHourlyCeiling     = 4
        cooldownMinutes      = 240
        mentionOnCritical    = $true
        smtpHost             = $smtpHost
        smtpPort             = $smtpPort
        smtpUseSsl           = $smtpSsl
    }
    ai        = [ordered]@{
        enabled           = $aiEnabled
        triageMinSeverity = 'High'
        triageModel       = 'sonnet'
        reportModel       = 'opus'
        monthlyBudgetUsd  = 15
    }
    scan      = [ordered]@{
        watchPaths          = @($watchPath)
        autoQuarantine      = $autoQ
        quarantineThreshold = 60
        virusTotalEnabled   = $vtEnabled
        uploadToVirusTotal  = $false
        settleMs            = 2500
        maxFileSizeMb       = 512
    }
    thresholds = [ordered]@{ failedLogonBurst = 10 }
    retention  = [ordered]@{ findingsDays = 120; reportsDays = 365; evidenceDays = 180 }
    remote     = [ordered]@{ hosts = @() }
}
$path = Save-NGConfig -Config ([pscustomobject]$config)
Write-Host ''
Write-Host "  Configuration written to $path" -ForegroundColor Green

if (Test-NGElevated) {
    Repair-NGAcl | Out-Null
    $lockDesc = if ((Get-NGPlatform) -eq 'Windows') { 'SYSTEM + Administrators' } else { 'root, mode 0600' }
    Write-Host "  Secret store locked to $lockDesc." -ForegroundColor Green
}

# --------------------------------------------------------------- test --------

if (-not $SkipTest) {
    Write-Head 'Delivery test'
    Write-Note 'An alerting system you have not tested is an alerting system that does not work.'
    if (AskYesNo 'Send a test alert now?' $true) {
        $res = Test-NGNotifyChannels -IncludeSms:$smsEnabled
        Write-Host ''
        foreach ($k in $res.PSObject.Properties.Name) {
            $ok = $res.$k
            if ($ok) { Write-Host "    $k : delivered" -ForegroundColor Green }
            else { Write-Host "    $k : FAILED - check the log in logs\" -ForegroundColor Red }
        }
        Write-Host ''
        Write-Note 'Check your Discord channel and your phone. If nothing arrived, re-run with -Reconfigure.'
    }
}

Write-Head 'Next steps'
$isWin = ((Get-NGPlatform) -eq 'Windows')
$elev = if ($isWin) { '.\' } else { 'sudo pwsh -File ./' }
$plain = if ($isWin) { '.\' } else { 'pwsh -File ./' }
Write-Host '    1. Register the scheduled jobs (elevated):' -ForegroundColor White
Write-Host "         ${elev}install/Register-Tasks.ps1" -ForegroundColor Yellow
Write-Host '    2. Take the first baseline and see your score:' -ForegroundColor White
Write-Host "         ${plain}agents/Invoke-HardeningAgent.ps1 -NoAlert" -ForegroundColor Yellow
Write-Host '    3. Review, then run the safe hardening tier (elevated):' -ForegroundColor White
Write-Host "         ${elev}harden/Apply-Tier1.ps1" -ForegroundColor Yellow
Write-Host '    4. Verify everything works end to end:' -ForegroundColor White
Write-Host "         ${plain}Test-NetGuard.ps1" -ForegroundColor Yellow
Write-Host ''
