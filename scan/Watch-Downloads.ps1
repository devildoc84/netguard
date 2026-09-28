<#
.SYNOPSIS
    NetGuard download watcher - scans files as they arrive.

.DESCRIPTION
    Watches the configured folders and runs the full scan pipeline on each new
    file. Runs as a long-lived process under Task Scheduler (start at logon,
    restart on failure).

    Two details that matter in practice:

    Settling. A FileSystemWatcher fires on creation, long before the browser has
    finished writing. Scanning immediately reads a partial file and produces a
    meaningless hash, so each path waits until its size has been stable for a
    moment and the file is no longer exclusively locked.

    Deduplication. Browsers generate .crdownload/.part temporaries and multiple
    events per file. Those are ignored and each final path is scanned once.

.PARAMETER Path
    Override the configured watch folders.

.PARAMETER ScanExisting
    Also scan everything already present at startup. Useful the first time.

.EXAMPLE
    .\Watch-Downloads.ps1 -ScanExisting
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [switch]$ScanExisting,
    [switch]$NoAlert
)

. (Join-Path (Split-Path -Parent $PSScriptRoot) 'agents\_Bootstrap.ps1')

$AGENT = 'scan'
$cfg = Get-NGConfig

$watchPaths = if ($Path) { $Path } else { @($cfg.scan.watchPaths) }
$watchPaths = @($watchPaths | Where-Object { $_ -and (Test-Path $_) })
if ((Get-NGCount $watchPaths) -eq 0) {
    Write-NGLog 'No valid watch paths configured; nothing to do.' -Level ERROR -Agent $AGENT
    exit 1
}

# Transient artefacts of an in-progress download. Scanning these wastes time and
# produces hashes for files that will not exist a second later.
$ignorePattern = '\.(crdownload|part|partial|tmp|download|!ut|opdownload)$|^~\$|\.quarantined$'

$script:Pending = [System.Collections.Concurrent.ConcurrentDictionary[string, datetime]]::new()
$script:Seen = @{}

function Test-FileSettled {
    <# A file is ready when its size stopped changing and nothing holds it open. #>
    param([string]$FilePath, [int]$SettleMs = 2500)
    try {
        if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return $false }
        $a = (Get-Item -LiteralPath $FilePath -ErrorAction Stop).Length
        Start-Sleep -Milliseconds $SettleMs
        if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return $false }
        $b = (Get-Item -LiteralPath $FilePath -ErrorAction Stop).Length
        if ($a -ne $b) { return $false }
        # Exclusive open proves the writer has let go.
        $fs = [IO.File]::Open($FilePath, 'Open', 'Read', 'None')
        $fs.Close()
        $true
    }
    catch { $false }
}

function Invoke-ScanAndRespond {
    param([string]$FilePath)

    if ($FilePath -match $ignorePattern) { return }
    $key = $FilePath.ToLower()
    # Re-scan only if the file changed since we last looked at it.
    try { $stamp = (Get-Item -LiteralPath $FilePath -ErrorAction Stop).LastWriteTimeUtc.Ticks } catch { return }
    if ($script:Seen.ContainsKey($key) -and $script:Seen[$key] -eq $stamp) { return }

    if (-not (Test-FileSettled -FilePath $FilePath -SettleMs ([int]$cfg.scan.settleMs))) {
        Write-NGLog "Still being written, will retry: $(Split-Path $FilePath -Leaf)" -Level DEBUG -Agent $AGENT -Quiet
        return
    }
    $script:Seen[$key] = $stamp

    try {
        $item = Get-Item -LiteralPath $FilePath -ErrorAction Stop
        $maxBytes = [int]$cfg.scan.maxFileSizeMb * 1MB
        if ($item.Length -gt $maxBytes) {
            Write-NGLog "Skipping $($item.Name): $([math]::Round($item.Length/1MB)) MB exceeds the $($cfg.scan.maxFileSizeMb) MB limit." -Level WARN -Agent $AGENT
            return
        }

        $result = Invoke-NGFileScan -Path $FilePath `
            -SkipVirusTotal:(-not $cfg.scan.virusTotalEnabled) `
            -SkipAI:(-not $cfg.ai.enabled)

        $quarantined = $false
        if ($cfg.scan.autoQuarantine -and [int]$result.score -ge [int]$cfg.scan.quarantineThreshold) {
            $q = Move-NGToQuarantine -ScanResult $result
            $quarantined = [bool]$q.quarantined
        }

        if ($result.verdict -ne 'allow') {
            $finding = ConvertTo-NGScanFinding -ScanResult $result -Quarantined:$quarantined
            $null = $finding | Add-NGFinding
            if (-not $NoAlert) { $null = $finding | Send-NGAlert }
        }
    }
    catch {
        Write-NGLog "Scan failed for ${FilePath}: $($_.Exception.Message)" -Level ERROR -Agent $AGENT
    }
}

Write-NGLog "Download watcher starting on: $($watchPaths -join '; ')" -Agent $AGENT

if ($ScanExisting) {
    foreach ($p in $watchPaths) {
        $existing = @(Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue)
        Write-NGLog "Scanning $(Get-NGCount $existing) pre-existing file(s) in $p" -Agent $AGENT
        foreach ($f in $existing) { Invoke-ScanAndRespond -FilePath $f.FullName }
    }
}

$watchers = @()
foreach ($p in $watchPaths) {
    $w = New-Object System.IO.FileSystemWatcher
    $w.Path = $p
    $w.IncludeSubdirectories = $false
    $w.NotifyFilter = [IO.NotifyFilters]::FileName -bor [IO.NotifyFilters]::LastWrite -bor [IO.NotifyFilters]::Size
    $w.EnableRaisingEvents = $true
    $watchers += $w

    # The handler only records the path. Doing the scan inside the event would
    # block the watcher thread and drop subsequent events during a long scan.
    $action = {
        $fp = $Event.SourceEventArgs.FullPath
        [void]$script:Pending.TryAdd($fp, (Get-Date))
    }
    foreach ($evt in 'Created', 'Renamed', 'Changed') {
        Register-ObjectEvent -InputObject $w -EventName $evt -Action $action | Out-Null
    }
}

Write-NGLog 'Watcher active. Press Ctrl+C to stop.' -Agent $AGENT
Send-NGHeartbeat -Agent $AGENT

$lastHeartbeat = Get-Date
try {
    while ($true) {
        Start-Sleep -Milliseconds 900

        if ($script:Pending.Count -gt 0) {
            foreach ($k in @($script:Pending.Keys)) {
                $when = [datetime]::MinValue
                if ($script:Pending.TryRemove($k, [ref]$when)) {
                    Invoke-ScanAndRespond -FilePath $k
                }
            }
        }

        # Periodic heartbeat so a dead watcher is detectable. Without this, a
        # crashed watcher is indistinguishable from a quiet week of no downloads.
        if (((Get-Date) - $lastHeartbeat).TotalMinutes -ge 15) {
            Send-NGHeartbeat -Agent $AGENT
            $lastHeartbeat = Get-Date
        }
    }
}
finally {
    Write-NGLog 'Watcher stopping.' -Agent $AGENT
    foreach ($w in $watchers) { try { $w.EnableRaisingEvents = $false; $w.Dispose() } catch { } }
    Get-EventSubscriber | Where-Object { $_.SourceObject -is [System.IO.FileSystemWatcher] } |
        Unregister-Event -ErrorAction SilentlyContinue
}
