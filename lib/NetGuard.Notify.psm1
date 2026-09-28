<#
    NetGuard.Notify - alert delivery with severity routing, dedupe and rate limits.

    Two channels:
      Discord webhook  - the rich channel. Full detail, embeds, colour by severity.
      Email-to-SMS     - the phone channel. Hard 140-char budget, criticals only
                         by default, because carrier gateways throttle and drop.

    The suppression logic here is the difference between a system you keep and one
    you mute in week two. Three layers:
      1. Severity floor per channel.
      2. Per-fingerprint cooldown, so the same finding does not page you hourly.
      3. Per-channel hourly ceiling, which collapses overflow into one digest
         rather than dropping alerts silently.
#>

# Dependencies are loaded by Import-NGStack (lib/NetGuard.Platform.psm1),
# in order, exactly once. This module deliberately does NOT import its
# siblings: an Import-Module -Force from inside a module unloads and
# reloads the shared module graph mid-import, discarding module-scoped
# state and breaking command resolution in ways that only show up at
# runtime. Load order belongs to one place, not nine.
# Discord embed colours, decimal RGB.
$script:NGColor = @{
    Info     = 8421504    # grey
    Low      = 3447003    # blue
    Medium   = 16092160   # amber
    High     = 15105570   # orange
    Critical = 15158332   # red
}

# Email-to-SMS gateways. Deliberately a lookup, not free text, so the wizard can
# validate. MMS gateways are used where the SMS one is retired or lossy.
$script:NGCarrierGateway = [ordered]@{
    'Verizon'            = 'vtext.com'
    'AT&T'               = 'txt.att.net'
    'T-Mobile'           = 'tmomail.net'
    'Sprint'             = 'messaging.sprintpcs.com'
    'US Cellular'        = 'email.uscc.net'
    'Cricket'            = 'mms.cricketwireless.net'
    'Boost Mobile'       = 'sms.myboostmobile.com'
    'Metro by T-Mobile'  = 'mymetropcs.com'
    'Google Fi'          = 'msg.fi.google.com'
    'Mint Mobile'        = 'tmomail.net'
    'Visible'            = 'vtext.com'
    'Xfinity Mobile'     = 'vtext.com'
    'Spectrum Mobile'    = 'vtext.com'
    'Straight Talk'      = 'vtext.com'
    'Rogers (CA)'        = 'pcs.rogers.com'
    'Bell (CA)'          = 'txt.bell.ca'
    'Telus (CA)'         = 'msg.telus.com'
    'Freedom (CA)'       = 'txt.freedommobile.ca'
}

function Get-NGCarrierGateway { $script:NGCarrierGateway }

# ------------------------------------------------------------- suppression ----

function Test-NGShouldSend {
    <#
        Returns $true if this finding may go out on this channel right now.
        Updates the suppression ledger as a side effect when it allows a send.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Finding,
        [Parameter(Mandatory = $true)][string]$Channel,
        [int]$CooldownMinutes = 240,
        [int]$HourlyCeiling = 12
    )
    $stateName = "notify-$Channel"
    $st = Get-NGState -Name $stateName -Default ([pscustomobject]@{ sent = @(); window = @() })

    $now = (Get-Date).ToUniversalTime()

    # --- layer 2: per-fingerprint cooldown
    $sent = @{}
    if ($st.sent) {
        foreach ($p in $st.sent.PSObject.Properties) { $sent[$p.Name] = $p.Value }
    }
    if ($sent.ContainsKey($Finding.fingerprint)) {
        $last = [datetime]::MinValue
        if ([datetime]::TryParse($sent[$Finding.fingerprint], [ref]$last)) {
            if (($now - $last.ToUniversalTime()).TotalMinutes -lt $CooldownMinutes) {
                Write-NGLog "Suppressed (cooldown) on $Channel : $($Finding.title)" -Level DEBUG -Agent notify -Quiet
                return $false
            }
        }
    }

    # --- layer 3: hourly ceiling
    $window = @()
    if ($st.window) {
        foreach ($w in @($st.window)) {
            $t = [datetime]::MinValue
            if ([datetime]::TryParse($w, [ref]$t)) {
                if (($now - $t.ToUniversalTime()).TotalMinutes -lt 60) { $window += $w }
            }
        }
    }
    if ($window.Count -ge $HourlyCeiling) {
        # Record the overflow so the next digest can report it honestly.
        $ov = Get-NGState -Name "notify-overflow-$Channel" -Default ([pscustomobject]@{ count = 0; titles = @() })
        $titles = @($ov.titles) + $Finding.title
        if ($titles.Count -gt 40) { $titles = $titles[-40..-1] }
        Set-NGState -Name "notify-overflow-$Channel" -Value ([pscustomobject]@{
                count  = ([int]$ov.count + 1)
                titles = $titles
            })
        Write-NGLog "Suppressed (hourly ceiling $HourlyCeiling) on $Channel : $($Finding.title)" -Level WARN -Agent notify
        return $false
    }

    $sent[$Finding.fingerprint] = $now.ToString('o')
    # Prune fingerprints older than a week so the file cannot grow unbounded.
    foreach ($k in @($sent.Keys)) {
        $t = [datetime]::MinValue
        if ([datetime]::TryParse($sent[$k], [ref]$t)) {
            if (($now - $t.ToUniversalTime()).TotalDays -gt 7) { $sent.Remove($k) }
        }
    }
    $window += $now.ToString('o')

    Set-NGState -Name $stateName -Value ([pscustomobject]@{
            sent   = [pscustomobject]$sent
            window = $window
        })
    $true
}

# ---------------------------------------------------------------- Discord ----

function Send-NGDiscord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [string]$Description = '',
        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')][string]$Severity = 'Info',
        [hashtable]$Fields,
        [string]$Footer,
        [switch]$MentionEveryone
    )
    $hook = Get-NGSecret -Name 'DiscordWebhook' -AsPlainText
    if ([string]::IsNullOrWhiteSpace($hook)) {
        Write-NGLog 'Discord webhook not configured; skipping.' -Level WARN -Agent notify
        return $false
    }

    # Discord caps: title 256, description 4096, 25 fields, field value 1024.
    if ($Title.Length -gt 250) { $Title = $Title.Substring(0, 247) + '...' }
    if ($Description.Length -gt 4000) { $Description = $Description.Substring(0, 3997) + '...' }

    $embedFields = @()
    if ($Fields) {
        foreach ($k in $Fields.Keys) {
            if ($embedFields.Count -ge 25) { break }
            $v = [string]$Fields[$k]
            if ([string]::IsNullOrWhiteSpace($v)) { $v = '-' }
            if ($v.Length -gt 1020) { $v = $v.Substring(0, 1017) + '...' }
            $embedFields += @{ name = [string]$k; value = $v; inline = ($v.Length -lt 40) }
        }
    }

    if (-not $Footer) { $Footer = "NetGuard - $(Get-NGHostName)" }

    $payload = @{
        username    = 'NetGuard'
        embeds      = @(@{
                title       = "$Title"
                description = $Description
                color       = $script:NGColor[$Severity]
                timestamp   = (Get-Date).ToUniversalTime().ToString('o')
                footer      = @{ text = $Footer }
                fields      = $embedFields
            })
        # Never let finding text trigger mentions; only our own explicit flag can.
        allowed_mentions = @{ parse = @() }
    }
    if ($MentionEveryone) {
        $payload.content = '@everyone'
        $payload.allowed_mentions = @{ parse = @('everyone') }
    }

    $json = $payload | ConvertTo-Json -Depth 10 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)

    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-RestMethod -Uri $hook -Method Post -Body $bytes `
                -ContentType 'application/json; charset=utf-8' -TimeoutSec 25 -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            $status = $null
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 429) {
                $wait = [math]::Pow(2, $attempt)
                Write-NGLog "Discord rate limited, backing off ${wait}s." -Level WARN -Agent notify
                Start-Sleep -Seconds $wait
                continue
            }
            if ($attempt -eq 4) {
                Write-NGLog "Discord send failed: $($_.Exception.Message)" -Level ERROR -Agent notify
                return $false
            }
            Start-Sleep -Seconds ($attempt * 2)
        }
    }
    $false
}

# ----------------------------------------------------------- email-to-SMS ----

function Send-NGSms {
    <#
        Carrier gateways silently truncate and sometimes drop. Keep the body
        under ~140 chars, put the single most actionable fact first, and never
        rely on this as the only record of an alert - Discord holds the detail.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Body)

    $cfg = Get-NGConfig
    $to = Get-NGSecret -Name 'SmsAddress' -AsPlainText
    $smtpUser = Get-NGSecret -Name 'SmtpUser' -AsPlainText
    $smtpPass = Get-NGSecret -Name 'SmtpPassword' -AsPlainText

    if ([string]::IsNullOrWhiteSpace($to)) {
        Write-NGLog 'SMS address not configured; skipping.' -Level WARN -Agent notify
        return $false
    }

    $body = ($Body -replace '\s+', ' ').Trim()
    if ($body.Length -gt 140) { $body = $body.Substring(0, 137) + '...' }

    try {
        $msg = New-Object System.Net.Mail.MailMessage
        $msg.From = New-Object System.Net.Mail.MailAddress($smtpUser, 'NetGuard')
        foreach ($addr in ($to -split '[;,]')) {
            $a = $addr.Trim()
            if ($a) { $msg.To.Add($a) }
        }
        # Gateways prepend the subject to the message body, so leave it empty.
        $msg.Subject = ''
        $msg.Body = $body
        $msg.IsBodyHtml = $false

        $smtp = New-Object System.Net.Mail.SmtpClient($cfg.notify.smtpHost, [int]$cfg.notify.smtpPort)
        $smtp.EnableSsl = [bool]$cfg.notify.smtpUseSsl
        $smtp.Timeout = 30000
        $smtp.Credentials = New-Object System.Net.NetworkCredential($smtpUser, $smtpPass)
        $smtp.Send($msg)
        $msg.Dispose()
        Write-NGLog "SMS dispatched via $($cfg.notify.smtpHost)." -Agent notify
        return $true
    }
    catch {
        Write-NGLog "SMS send failed: $($_.Exception.Message)" -Level ERROR -Agent notify
        return $false
    }
}

# ----------------------------------------------------------------- router ----

function Send-NGAlert {
    <#
        The single entry point collectors use. Applies routing and suppression,
        then fans out. Returns the finding so it can stay in a pipeline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]$Finding,
        [switch]$Force
    )
    begin {
        $cfg = $null
        try { $cfg = Get-NGConfig } catch { Write-NGLog 'No config; alerts disabled.' -Level ERROR -Agent notify }
    }
    process {
        foreach ($f in @($Finding)) {
            if ($null -eq $f) { continue }
            if (-not $cfg) { $f; continue }

            $rank = [int]$f.severityRank
            $discordFloor = Get-NGSeverityRank $cfg.notify.discordMinSeverity
            $smsFloor = Get-NGSeverityRank $cfg.notify.smsMinSeverity

            $desc = $f.detail
            if ($f.recommendation) { $desc = "$desc`n`n**Recommended action:** $($f.recommendation)" }

            $fields = [ordered]@{
                Severity = $f.severity
                Host     = $f.host
                Category = $f.category
                Agent    = $f.agent
            }
            if ($f.evidence) {
                $ev = ($f.evidence | ConvertTo-Json -Depth 6)
                if ($ev.Length -gt 1000) { $ev = $ev.Substring(0, 997) + '...' }
                $fields['Evidence'] = "``````json`n$ev`n``````"
            }

            if ($cfg.notify.discordEnabled -and ($rank -ge $discordFloor)) {
                if ($Force -or (Test-NGShouldSend -Finding $f -Channel 'discord' `
                            -CooldownMinutes $cfg.notify.cooldownMinutes `
                            -HourlyCeiling $cfg.notify.discordHourlyCeiling)) {
                    Send-NGDiscord -Title $f.title -Description $desc -Severity $f.severity `
                        -Fields $fields -MentionEveryone:($f.severity -eq 'Critical' -and $cfg.notify.mentionOnCritical) | Out-Null
                }
            }

            if ($cfg.notify.smsEnabled -and ($rank -ge $smsFloor)) {
                if ($Force -or (Test-NGShouldSend -Finding $f -Channel 'sms' `
                            -CooldownMinutes ([int]$cfg.notify.cooldownMinutes * 2) `
                            -HourlyCeiling $cfg.notify.smsHourlyCeiling)) {
                    Send-NGSms -Body ("NG {0} {1}: {2}" -f $f.severity.ToUpper(), $f.host, $f.title) | Out-Null
                }
            }
            $f
        }
    }
}

function Send-NGOverflowDigest {
    <#
        Reports what the hourly ceiling swallowed, so suppression is visible
        rather than a silent hole in coverage. Called at the end of each agent run.
    #>
    foreach ($ch in 'discord', 'sms') {
        $ov = Get-NGState -Name "notify-overflow-$ch" -Default $null
        if (-not $ov -or [int]$ov.count -le 0) { continue }
        $titles = (@($ov.titles) | Select-Object -Last 15) -join "`n- "
        if ($ch -eq 'discord') {
            Send-NGDiscord -Title "$([int]$ov.count) alerts suppressed by rate limit" `
                -Description "The hourly ceiling was hit. Most recent suppressed titles:`n- $titles" `
                -Severity Medium | Out-Null
        }
        else {
            Send-NGSms -Body ("NG: {0} alerts suppressed by rate limit - check Discord/report." -f [int]$ov.count) | Out-Null
        }
        Set-NGState -Name "notify-overflow-$ch" -Value ([pscustomobject]@{ count = 0; titles = @() })
    }
}

function Send-NGHeartbeat {
    <#
        Dead-man's switch. An agent that stops running produces silence, and
        silence is indistinguishable from "all clear" unless something positively
        asserts liveness. This writes a timestamp every run; Test-NGHeartbeat
        alerts when the newest one goes stale.
    #>
    param([string]$Agent = 'unknown')
    $hb = Get-NGState -Name 'heartbeat' -Default ([pscustomobject]@{})
    $map = @{}
    foreach ($p in $hb.PSObject.Properties) { $map[$p.Name] = $p.Value }
    $map[$Agent] = (Get-Date).ToUniversalTime().ToString('o')
    Set-NGState -Name 'heartbeat' -Value ([pscustomobject]$map)
}

function Test-NGHeartbeat {
    <# Emits findings for agents that have gone quiet past their expected interval. #>
    param([hashtable]$ExpectedIntervalHours = @{ sentinel = 2; discovery = 26; hardening = 26 })
    $hb = Get-NGState -Name 'heartbeat' -Default $null
    if (-not $hb) { return @() }
    $now = (Get-Date).ToUniversalTime()
    $out = @()
    foreach ($agent in $ExpectedIntervalHours.Keys) {
        $prop = $hb.PSObject.Properties[$agent]
        if (-not $prop) { continue }
        $t = [datetime]::MinValue
        if (-not [datetime]::TryParse($prop.Value, [ref]$t)) { continue }
        $age = ($now - $t.ToUniversalTime()).TotalHours
        if ($age -gt $ExpectedIntervalHours[$agent]) {
            $out += New-NGFinding -Category 'Availability' -Severity 'High' -Agent 'notify' `
                -Title "NetGuard $agent agent has not run in $([math]::Round($age,1))h" `
                -Detail "Expected at least every $($ExpectedIntervalHours[$agent])h. A monitoring agent that is not running produces silence, not safety." `
                -Recommendation "Check Task Scheduler for the NetGuard\$agent task and review logs\netguard-*.jsonl for the last error." `
                -FingerprintSeed "heartbeat-stale-$agent"
        }
    }
    , @($out)
}

function Test-NGNotifyChannels {
    <# Used by the wizard and by Register-Tasks to prove delivery actually works. #>
    [CmdletBinding()]
    param([switch]$IncludeSms)
    $results = [ordered]@{}
    $results['discord'] = Send-NGDiscord -Title 'NetGuard test alert' `
        -Description "If you can read this, the Discord channel is wired up correctly.`n`nThis is a configuration test from ``$(Get-NGHostName)``." `
        -Severity Info -Fields ([ordered]@{ Test = 'true'; Time = (Get-Date).ToString('u') })
    if ($IncludeSms) {
        $results['sms'] = Send-NGSms -Body "NetGuard test from $(Get-NGHostName) - SMS path works."
    }
    [pscustomobject]$results
}

Export-ModuleMember -Function *
