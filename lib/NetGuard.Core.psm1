<#
    NetGuard.Core - configuration, secrets, state, logging, diffing.

    Platform-neutral. Anything needing OS-specific behaviour (crypto primitives,
    file permissions, elevation, subnet enumeration) is delegated to the loaded
    provider. There are no OS branches in this file.

    PowerShell 5.1 compatible: Windows ships 5.1 and many users will never
    install 7, so shared code avoids ??, ternaries and && entirely.

    StrictMode is deliberately NOT enabled: these functions run unattended
    against data whose shape changes between OS versions, and a missing property
    should degrade a single check rather than kill the run.
#>

$script:NGRoot = Split-Path -Parent $PSScriptRoot

# Severity ladder. Routing, dedupe and reporting all key off these ranks.
$script:NGSeverity = [ordered]@{
    Info = 0; Low = 1; Medium = 2; High = 3; Critical = 4
}

function Get-NGRoot { $script:NGRoot }

function Get-NGSeverityRank {
    param([string]$Severity)
    if ($script:NGSeverity.Contains($Severity)) { return $script:NGSeverity[$Severity] }
    0
}

function Get-NGPath {
    param([Parameter(Mandatory = $true)][string]$Leaf)
    # Normalise separators so callers can use either style on any platform.
    $sep = [IO.Path]::DirectorySeparatorChar
    Join-Path $script:NGRoot ($Leaf -replace '[\\/]', $sep)
}

function Initialize-NGTree {
    foreach ($d in 'config', 'state', 'logs', 'reports', 'quarantine', 'evidence', 'baseline', 'harden') {
        $p = Get-NGPath $d
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
}

# ---------------------------------------------------------------- logging ----

function Write-NGLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')][string]$Level = 'INFO',
        [string]$Agent = 'core',
        [hashtable]$Data,
        [switch]$Quiet
    )
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $rec = [ordered]@{ ts = $ts; level = $Level; agent = $Agent; msg = $Message }
    if ($Data) { $rec.data = $Data }

    $logDir = Get-NGPath 'logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $file = Join-Path $logDir ('netguard-{0}.jsonl' -f (Get-Date -Format 'yyyy-MM-dd'))

    $line = ($rec | ConvertTo-Json -Compress -Depth 8)
    # Retry briefly - several agents can be logging concurrently.
    for ($i = 0; $i -lt 5; $i++) {
        try { Add-Content -LiteralPath $file -Value $line -Encoding utf8 -ErrorAction Stop; break }
        catch { Start-Sleep -Milliseconds 80 }
    }

    if (-not $Quiet) {
        $colors = @{ DEBUG = 'DarkGray'; INFO = 'Gray'; WARN = 'Yellow'; ERROR = 'Red' }
        Write-Host ('[{0}] {1,-5} {2,-14} {3}' -f $ts.Substring(11, 8), $Level, $Agent, $Message) -ForegroundColor $colors[$Level]
    }
}

# ----------------------------------------------------------------- config ----

function Get-NGConfig {
    [CmdletBinding()]
    param()
    $p = Get-NGPath 'config/netguard.config.json'
    if (-not (Test-Path $p)) {
        throw "NetGuard is not configured. Run Setup-NetGuard.ps1 first (missing $p)."
    }
    Get-Content -LiteralPath $p -Raw -Encoding utf8 | ConvertFrom-Json
}

function Save-NGConfig {
    param([Parameter(Mandatory = $true)]$Config)
    Initialize-NGTree
    $p = Get-NGPath 'config/netguard.config.json'
    ($Config | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $p -Encoding utf8
    $p
}

# ---------------------------------------------------------------- secrets ----
<#
    The cipher is provider-supplied: DPAPI on Windows, AES-256-CBC + HMAC with a
    root-owned key file on Linux. In both cases the FILE PERMISSIONS are the real
    control, not the cipher, because the agents run as SYSTEM/root and must be
    able to decrypt unattended.
#>

function Protect-NGFile {
    <# Delegates to the provider. No-ops with one warning if unprivileged. #>
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path $Path)) { return }
    if (-not (Get-Command Protect-NGFilePath -ErrorAction SilentlyContinue)) { return }
    $ok = Protect-NGFilePath -Path $Path
    if (-not $ok -and -not $script:NGAclWarned) {
        Write-NGLog 'Not privileged: secret files keep their default permissions for now. Re-run Setup-NetGuard.ps1 elevated to lock them down.' -Level WARN
        $script:NGAclWarned = $true
    }
}

function Repair-NGAcl {
    <# Re-applies strict permissions to every sensitive file. Needs privilege. #>
    [CmdletBinding()]
    param()
    if (-not (Test-NGElevated)) {
        Write-NGLog 'Repair-NGAcl requires Administrator (Windows) or root (Linux).' -Level ERROR
        return $false
    }
    $targets = @(
        (Get-NGPath 'state/.ngkey')
        (Get-NGPath 'state/secrets.json')
        (Get-NGPath 'config/netguard.config.json')
    )
    $done = 0
    foreach ($t in $targets) { if (Test-Path $t) { Protect-NGFile -Path $t; $done++ } }
    Write-NGLog "Tightened permissions on $done sensitive file(s)."
    $true
}

function Get-NGEntropy {
    <#
        Additional key material stored beside the secret store, so a stolen copy
        of either file alone is useless.
    #>
    $kp = Get-NGPath 'state/.ngkey'
    if (-not (Test-Path $kp)) {
        Initialize-NGTree
        $bytes = New-Object byte[] 64
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($bytes)
        [IO.File]::WriteAllBytes($kp, $bytes)
        Protect-NGFile -Path $kp
    }
    try { [IO.File]::ReadAllBytes($kp) }
    catch [System.UnauthorizedAccessException] {
        throw "Cannot read the NetGuard key at $kp. It is restricted to administrators/root, so run this elevated."
    }
}

function Set-NGSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )
    Initialize-NGTree
    $store = Get-NGPath 'state/secrets.json'
    $data = @{}
    if (Test-Path $store) {
        $existing = Get-Content -LiteralPath $store -Raw -Encoding utf8 | ConvertFrom-Json
        foreach ($p in $existing.PSObject.Properties) { $data[$p.Name] = $p.Value }
    }
    $plain = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $cipher = Protect-NGSecretBytes -Bytes $plain -Entropy (Get-NGEntropy)
    [Array]::Clear($plain, 0, $plain.Length)
    $data[$Name] = [Convert]::ToBase64String($cipher)

    ([pscustomobject]$data | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $store -Encoding utf8
    Protect-NGFile -Path $store
}

function Get-NGSecret {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name, [switch]$AsPlainText)
    $store = Get-NGPath 'state/secrets.json'
    if (-not (Test-Path $store)) { return $null }
    $data = Get-Content -LiteralPath $store -Raw -Encoding utf8 | ConvertFrom-Json
    $prop = $data.PSObject.Properties[$Name]
    if (-not $prop) { return $null }
    try {
        $cipher = [Convert]::FromBase64String($prop.Value)
        $plain = Unprotect-NGSecretBytes -Bytes $cipher -Entropy (Get-NGEntropy)
        $s = [System.Text.Encoding]::UTF8.GetString($plain)
        [Array]::Clear($plain, 0, $plain.Length)
        if ($AsPlainText) { return $s }
        # Build the SecureString one character at a time. Same result as
        # ConvertTo-SecureString -AsPlainText, without the analyzer error.
        $secure = New-Object System.Security.SecureString
        foreach ($ch in $s.ToCharArray()) { $secure.AppendChar($ch) }
        $secure.MakeReadOnly()
        return $secure
    }
    catch {
        Write-NGLog "Failed to decrypt secret '$Name' - was it written on another machine? $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Test-NGSecret {
    param([Parameter(Mandatory = $true)][string]$Name)
    -not [string]::IsNullOrWhiteSpace((Get-NGSecret -Name $Name -AsPlainText))
}

# ------------------------------------------------------------------ state ----

function Get-NGState {
    param([Parameter(Mandatory = $true)][string]$Name, $Default = $null)
    $p = Get-NGPath ('state/{0}.json' -f $Name)
    if (-not (Test-Path $p)) { return $Default }
    try { Get-Content -LiteralPath $p -Raw -Encoding utf8 | ConvertFrom-Json }
    catch { Write-NGLog "Corrupt state file $p, ignoring." -Level WARN; $Default }
}

function Set-NGState {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)]$Value)
    Initialize-NGTree
    $p = Get-NGPath ('state/{0}.json' -f $Name)
    ($Value | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $p -Encoding utf8
}

# --------------------------------------------------------------- findings ----

function New-NGFinding {
    <#
        Canonical finding object. Every collector emits these and nothing else,
        which is what lets notification, AI triage and reporting stay generic.

        FingerprintSeed controls dedupe identity: include the volatile part of a
        finding (a device MAC, a file hash) so recurrences collapse, but keep
        genuinely new events distinct.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Title,
        [string]$Detail = '',
        [string]$Recommendation = '',
        $Evidence = $null,
        [string]$Agent = 'unknown',
        [string]$HostName,
        [string]$FingerprintSeed
    )
    if (-not $HostName) { $HostName = [System.Net.Dns]::GetHostName() }
    if (-not $FingerprintSeed) { $FingerprintSeed = "$Category|$Title" }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$HostName|$FingerprintSeed"))
    $fp = (([BitConverter]::ToString($hash)) -replace '-', '').Substring(0, 16).ToLower()

    [pscustomobject][ordered]@{
        id             = [guid]::NewGuid().ToString()
        ts             = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        host           = $HostName
        agent          = $Agent
        category       = $Category
        severity       = $Severity
        severityRank   = (Get-NGSeverityRank $Severity)
        title          = $Title
        detail         = $Detail
        recommendation = $Recommendation
        evidence       = $Evidence
        fingerprint    = $fp
    }
}

function Add-NGFinding {
    param([Parameter(Mandatory = $true, ValueFromPipeline = $true)]$Finding)
    begin {
        Initialize-NGTree
        $ledger = Get-NGPath 'state/findings.jsonl'
    }
    process {
        foreach ($f in $Finding) {
            if ($null -eq $f) { continue }
            $line = ($f | ConvertTo-Json -Compress -Depth 12)
            for ($i = 0; $i -lt 5; $i++) {
                try { Add-Content -LiteralPath $ledger -Value $line -Encoding utf8 -ErrorAction Stop; break }
                catch { Start-Sleep -Milliseconds 80 }
            }
            $f
        }
    }
}

function Get-NGFindings {
    param(
        [int]$SinceDays = 7,
        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')][string]$MinSeverity = 'Info'
    )
    $ledger = Get-NGPath 'state/findings.jsonl'
    if (-not (Test-Path $ledger)) { return @() }
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-$SinceDays)
    $min = Get-NGSeverityRank $MinSeverity
    $out = New-Object System.Collections.Generic.List[psobject]
    foreach ($line in (Get-Content -LiteralPath $ledger -Encoding utf8)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $o = $line | ConvertFrom-Json } catch { continue }
        $t = [datetime]::MinValue
        if ([datetime]::TryParse($o.ts, [ref]$t)) {
            if ($t.ToUniversalTime() -ge $cutoff -and $o.severityRank -ge $min) { $out.Add($o) }
        }
    }
    , @($out)
}

function Compress-NGLedger {
    param([int]$RetentionDays = 120)
    $ledger = Get-NGPath 'state/findings.jsonl'
    if (-not (Test-Path $ledger)) { return }
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-$RetentionDays)
    $keep = New-Object System.Collections.Generic.List[string]
    $archive = New-Object System.Collections.Generic.List[string]
    foreach ($line in (Get-Content -LiteralPath $ledger -Encoding utf8)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $old = $false
        $t = [datetime]::MinValue
        try {
            $o = $line | ConvertFrom-Json
            if ([datetime]::TryParse($o.ts, [ref]$t)) { $old = $t.ToUniversalTime() -lt $cutoff }
        }
        catch { }
        if ($old) { $archive.Add($line) } else { $keep.Add($line) }
    }
    if ($archive.Count -gt 0) {
        Add-Content -LiteralPath (Get-NGPath 'state/findings.archive.jsonl') -Value $archive -Encoding utf8
        Set-Content -LiteralPath $ledger -Value $keep -Encoding utf8
        Write-NGLog "Archived $($archive.Count) findings older than $RetentionDays days."
    }
}

# ------------------------------------------------------------------ diffs ----

function Compare-NGSnapshot {
    <#
        Generic keyed diff between a stored baseline and a fresh snapshot. Every
        collector gets drift detection from this instead of hand-rolling
        comparisons.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][array]$Baseline,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()][array]$Current,
        [Parameter(Mandatory = $true)][string]$Key,
        [string[]]$CompareProperties
    )
    $bMap = @{}; $cMap = @{}
    foreach ($b in $Baseline) { if ($b -and $b.$Key) { $bMap[[string]$b.$Key] = $b } }
    foreach ($c in $Current) { if ($c -and $c.$Key) { $cMap[[string]$c.$Key] = $c } }

    $added = @(); $removed = @(); $changed = @()
    foreach ($k in $cMap.Keys) { if (-not $bMap.ContainsKey($k)) { $added += $cMap[$k] } }
    foreach ($k in $bMap.Keys) { if (-not $cMap.ContainsKey($k)) { $removed += $bMap[$k] } }

    if ($CompareProperties) {
        foreach ($k in $cMap.Keys) {
            if (-not $bMap.ContainsKey($k)) { continue }
            $deltas = @()
            foreach ($prop in $CompareProperties) {
                $ov = $null; $nv = $null
                if ($bMap[$k].PSObject.Properties[$prop]) { $ov = $bMap[$k].$prop }
                if ($cMap[$k].PSObject.Properties[$prop]) { $nv = $cMap[$k].$prop }
                if ("$ov" -ne "$nv") { $deltas += [pscustomobject]@{ property = $prop; from = $ov; to = $nv } }
            }
            if ($deltas.Count -gt 0) {
                $changed += [pscustomobject]@{ key = $k; current = $cMap[$k]; deltas = $deltas }
            }
        }
    }
    [pscustomobject]@{
        Added = $added; Removed = $removed; Changed = $changed
        HasDrift = (($added.Count + $removed.Count + $changed.Count) -gt 0)
    }
}

<#
    Baselines are stored as {"items":[...]} rather than as a bare JSON array.

    A bare array cannot survive the round trip reliably: piping a comma-wrapped
    array to ConvertTo-Json emits {"value":[...],"Count":n}, and a single-element
    array serialises as an object instead of a list. Either way the reader gets
    one opaque blob whose .key is null, so Compare-NGSnapshot matches nothing and
    every item looks new on the next run - drift detection that silently reports
    everything as changed while appearing to work.
#>

function Get-NGBaseline {
    <#
        A baseline is only meaningful for the host and platform that recorded it.

        If either differs, the baseline is treated as ABSENT so it is relearned
        silently rather than diffed. Without this, a tree copied between machines
        - or restored from a backup, or shared over a network path - reports
        every account, service and certificate on the new host as newly created.
        That is hundreds of high-severity findings that are all wrong, and it
        arrives looking exactly like a compromise.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)
    $p = Get-NGPath ('baseline/{0}.json' -f $Name)
    if (-not (Test-Path $p)) { return $null }
    try {
        $o = Get-Content -LiteralPath $p -Raw -Encoding utf8 | ConvertFrom-Json
        if ($null -eq $o) { return $null }

        if ($o.PSObject.Properties['items']) {
            $thisHost = Get-NGHostName
            $thisPlatform = if (Get-Command Get-NGPlatform -ErrorAction SilentlyContinue) { Get-NGPlatform } else { 'unknown' }
            $recordedHost = "$($o.host)"
            $recordedPlatform = "$($o.platform)"

            # Older baselines carry no identity; accept those rather than
            # discarding a valid history on upgrade.
            if ($recordedHost -and ($recordedHost -ne $thisHost)) {
                Write-NGLog "Baseline '$Name' was recorded on host '$recordedHost' but this is '$thisHost'; relearning instead of diffing." -Level WARN
                return $null
            }
            if ($recordedPlatform -and ($recordedPlatform -ne $thisPlatform)) {
                Write-NGLog "Baseline '$Name' was recorded on $recordedPlatform but this is $thisPlatform; relearning instead of diffing." -Level WARN
                return $null
            }
            return , @($o.items)
        }
        return , @($o)   # tolerate a bare-array baseline from an older build
    }
    catch {
        Write-NGLog "Corrupt baseline '$Name'; treating as absent so it is relearned." -Level WARN
        $null
    }
}

function Set-NGBaseline {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowNull()]$Value
    )
    Initialize-NGTree
    $p = Get-NGPath ('baseline/{0}.json' -f $Name)
    $payload = [pscustomobject]@{
        savedAt  = (Get-Date).ToUniversalTime().ToString('o')
        host     = (Get-NGHostName)
        platform = if (Get-Command Get-NGPlatform -ErrorAction SilentlyContinue) { Get-NGPlatform } else { 'unknown' }
        count    = (Get-NGCount $Value)
        items    = @($Value)
    }
    Set-Content -LiteralPath $p -Value (ConvertTo-Json -InputObject $payload -Depth 20) -Encoding utf8
}

# -------------------------------------------------- null and type safety -----

function ConvertTo-NGArray {
    <#
        Null-safe array coercion.

        PowerShell's @($null) yields a ONE-element array containing $null, so the
        idiomatic @($x).Count silently reports 1 for an absent value. That bug
        produced a phantom Defender exclusion and pushed a check down the wrong
        branch, so every count in the collectors goes through here.
    #>
    param([Parameter(Position = 0)][AllowNull()]$InputObject)
    $out = New-Object System.Collections.ArrayList
    if ($null -ne $InputObject) {
        foreach ($i in $InputObject) {
            if ($null -ne $i -and "$i" -ne '') { [void]$out.Add($i) }
        }
    }
    # Unary comma keeps a 0- or 1-element result from being unrolled.
    , $out.ToArray()
}

function Get-NGCount {
    <#
        Null-safe count. Counts by iteration rather than by wrapping in an array,
        because ConvertTo-NGArray returns a comma-wrapped result and re-wrapping
        that with @() counts the wrapper (always 1) instead of the contents.
    #>
    param([Parameter(Position = 0)][AllowNull()]$InputObject)
    if ($null -eq $InputObject) { return 0 }
    $n = 0
    foreach ($i in $InputObject) { if ($null -ne $i -and "$i" -ne '') { $n++ } }
    $n
}

function Test-NGAdminRestricted {
    <#
        Some platform cmdlets do not fail when called unprivileged - they return
        a sentinel string in place of the value. Counting or casting that invents
        data, so every consumer has to test for it explicitly.
    #>
    param([AllowNull()]$Value)
    $s = "$Value"
    ($s -like 'N/A*administrator*') -or ($s -like 'N/A: Must be*')
}

function Get-NGSafeInt {
    <#
        Cast to int without ever throwing.

        A bare [int] cast inside a hashtable initialiser is a TERMINATING error,
        and under $ErrorActionPreference='SilentlyContinue' it silently abandons
        the whole assignment. Defender returns both sentinel strings and UInt32
        sentinels like 4294967295, either of which previously took out an entire
        block of posture data - and a missing block reads as "nothing to report".
    #>
    param([AllowNull()]$Value, [int]$Default = -1)
    if ($null -eq $Value) { return $Default }
    if (Test-NGAdminRestricted $Value) { return $Default }
    $s = "$Value".Trim()
    if ($s -notmatch '^-?\d+$') { return $Default }
    try {
        $l = [int64]$s
        # 4294967295 (UInt32.MaxValue) is a "never happened" marker, not a real
        # value; clamping it would report a scan 5.8 million years overdue.
        if ($l -ge 4294967295) { return $Default }
        if ($l -gt [int]::MaxValue -or $l -lt [int]::MinValue) { return $Default }
        [int]$l
    }
    catch { $Default }
}

function Get-NGSafeBool {
    <# Tri-state bool: $null when the value is absent or a restricted sentinel. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if (Test-NGAdminRestricted $Value) { return $null }
    try { [bool]$Value } catch { $null }
}

# ------------------------------------------------------- portable paths ------
<#
    Windows-only environment variables do not exist on Linux: $env:TEMP,
    $env:COMPUTERNAME and $env:USERPROFILE are all $null there, and Join-Path
    with a null root throws "Cannot bind argument to parameter 'Path'". Shared
    code uses these helpers instead, so a path assumption cannot silently become
    a missing collector on one platform.
#>

function Get-NGHostName {
    try { [System.Net.Dns]::GetHostName() } catch { 'unknown-host' }
}

function Get-NGTempPath {
    param([string]$FileName)
    $base = [IO.Path]::GetTempPath()
    if ($FileName) { return (Join-Path $base $FileName) }
    $base
}

function Get-NGHomePath {
    $h = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    if (-not $h) { $h = $env:HOME }
    if (-not $h) { $h = $env:USERPROFILE }
    $h
}

function Get-NGDownloadsPath {
    $userHome = Get-NGHomePath
    if (-not $userHome) { return $null }
    Join-Path $userHome 'Downloads'
}

function Get-NGFileHashSafe {
    param([Parameter(Mandatory = $true)][string]$Path)
    try { (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { $null }
}

# ---------------------------------------------------------- MAC vendor -------

# Common consumer/enterprise OUI prefixes, for naming unknown LAN devices.
# Not exhaustive - a full IEEE OUI file can be dropped in as config/oui.json.
$script:NGOui = @{
    '9CA2F4' = 'Arris/CommScope'; '005056' = 'VMware'; '000C29' = 'VMware'; '001C14' = 'VMware'
    '00155D' = 'Microsoft Hyper-V'; '0050F2' = 'Microsoft'; '001DD8' = 'Microsoft'; '7C1E52' = 'Microsoft'
    'B827EB' = 'Raspberry Pi'; 'DCA632' = 'Raspberry Pi'; 'E45F01' = 'Raspberry Pi'
    '2CF05D' = 'Micro-Star (MSI)'; '001A11' = 'Google'; 'F4F5D8' = 'Google'; '3C5AB4' = 'Google'
    '18B430' = 'Nest'; '44650D' = 'Amazon'; 'FCA183' = 'Amazon'; '6854FD' = 'Amazon'; 'AC63BE' = 'Amazon'
    '001788' = 'Philips Hue'; 'ECFABC' = 'Espressif (IoT)'; '240AC4' = 'Espressif (IoT)'
    '3C71BF' = 'Espressif (IoT)'; '8CAAB5' = 'Espressif (IoT)'; '6C55B1' = 'Espressif/Generic IoT'
    '001132' = 'Synology'; '00E04C' = 'Realtek'; '001B63' = 'Apple'; 'F0189E' = 'Apple'
    'A45E60' = 'Apple'; 'DC2B2A' = 'Apple'; '3C0754' = 'Apple'; '001EC2' = 'Apple'
    '00095B' = 'Netgear'; '2C3033' = 'Netgear'; 'A040A0' = 'Netgear'; '001E2A' = 'Netgear'
    'C03F0E' = 'Netgear'; '000FB5' = 'Netgear'; '14CC20' = 'TP-Link'; '5091E3' = 'TP-Link'
    'A42BB0' = 'TP-Link'; 'EC086B' = 'TP-Link'; 'B0487A' = 'TP-Link'; '68FF7B' = 'TP-Link'
    '001E58' = 'D-Link'; '1CBDB9' = 'D-Link'; '3C2EF9' = 'Arris'; '0018E7' = 'Cameo (cameras)'
    '525400' = 'QEMU/KVM virtual'; '080027' = 'VirtualBox'; '00163E' = 'Xen virtual'
}

function Get-NGVendorFromMac {
    param([string]$Mac)
    if ([string]::IsNullOrWhiteSpace($Mac)) { return 'unknown' }
    $norm = ($Mac -replace '[-:\.]', '').ToUpper()
    if ($norm.Length -lt 6) { return 'unknown' }
    $prefix = $norm.Substring(0, 6)

    # An operator-supplied OUI file always wins.
    $ouiFile = Get-NGPath 'config/oui.json'
    if (Test-Path $ouiFile) {
        try {
            $ext = Get-Content -LiteralPath $ouiFile -Raw -Encoding utf8 | ConvertFrom-Json
            if ($ext.PSObject.Properties[$prefix]) { return $ext.$prefix }
        }
        catch { }
    }
    if ($script:NGOui.ContainsKey($prefix)) { return $script:NGOui[$prefix] }

    # Locally-administered bit set => randomised or virtual MAC.
    $second = [Convert]::ToInt32($norm.Substring(1, 1), 16)
    if ($second -band 2) { return 'randomised/virtual MAC' }
    "unknown ($prefix)"
}

# ------------------------------------------------------------- perimeter -----

function Get-NGPerimeter {
    <#
        External IP, UPnP exposure and gateway reachability.

        Platform-neutral: pure .NET sockets plus the provider's subnet lookup.
    #>
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue'
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

    $subnet = $null
    if (Get-Command Get-NGLocalSubnet -ErrorAction SilentlyContinue) { $subnet = Get-NGLocalSubnet }

    $o = [ordered]@{
        collectedAt = (Get-Date).ToUniversalTime().ToString('o')
        gateway     = if ($subnet) { $subnet.Gateway } else { $null }
        lanCidr     = if ($subnet) { $subnet.Cidr } else { $null }
        externalIp  = $null
    }

    # Two independent sources so one going down is not a false alarm.
    foreach ($svc in 'https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com') {
        try {
            $ip = (Invoke-RestMethod -Uri $svc -TimeoutSec 12 -ErrorAction Stop).ToString().Trim()
            if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') { $o.externalIp = $ip; $o.externalIpSource = $svc; break }
        }
        catch { }
    }

    # UPnP IGD presence. A gateway answering SSDP means anything on the LAN -
    # including malware and any compromised IoT device - can open inbound holes
    # in the router with no authentication and no record.
    $o.upnpIgdFound = $false
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = 2500
        $msg = "M-SEARCH * HTTP/1.1`r`nHOST:239.255.255.250:1900`r`nMAN:`"ssdp:discover`"`r`nMX:2`r`nST:urn:schemas-upnp-org:device:InternetGatewayDevice:1`r`n`r`n"
        $bytes = [Text.Encoding]::ASCII.GetBytes($msg)
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Parse('239.255.255.250'), 1900)
        $udp.Send($bytes, $bytes.Length, $ep) | Out-Null
        $remote = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $resp = [Text.Encoding]::ASCII.GetString($udp.Receive([ref]$remote))
        if ($resp -match 'InternetGatewayDevice') {
            $o.upnpIgdFound = $true
            $o.upnpResponder = $remote.Address.ToString()
        }
        $udp.Close()
    }
    catch { }

    # Gateway admin interface reachability - presence only, no credential testing.
    if ($subnet -and $subnet.Gateway) {
        $o.gatewayAdminPorts = @()
        foreach ($port in 80, 443, 8080, 8443, 22, 23) {
            try {
                $c = New-Object Net.Sockets.TcpClient
                if ($c.ConnectAsync($subnet.Gateway, $port).Wait(700)) { $o.gatewayAdminPorts += $port }
                $c.Close()
            }
            catch { }
        }
    }
    [pscustomobject]$o
}

Export-ModuleMember -Function *
