<#
    NetGuard.Scan - multi-stage analysis for files arriving from the internet.

    No single stage is trustworthy alone, so the pipeline stacks independent
    signals and scores them:

      1  Identity        SHA256 / size / type sniffing by magic bytes, not extension
      2  Provenance      Mark-of-the-Web: where the file actually came from
      3  Signature       Authenticode chain, timestamp, publisher
      4  Local AV        Defender on-demand scan via MpCmdRun
      5  Reputation      VirusTotal HASH LOOKUP ONLY - the file is never uploaded
      6  Static triage   Entropy, PE imports, embedded URLs, macros, LOLBin patterns
      7  AI review       Source-level intent analysis for scripts and macros
      8  Verdict         Deterministic score -> allow / suspicious / quarantine

    Why hash-only reputation by default: uploading a file sends its full contents
    to a third party and makes it permanently retrievable by anyone with the hash.
    For a personal machine that can mean leaking documents. Upload stays opt-in.

    Stage 7 is where AI earns its place: a novel PowerShell downloader has no hash
    reputation and may not trip a signature, but its intent is plain in its source.
#>

# Dependencies are loaded by Import-NGStack (lib/NetGuard.Platform.psm1),
# in order, exactly once. This module deliberately does NOT import its
# siblings: an Import-Module -Force from inside a module unloads and
# reloads the shared module graph mid-import, discarding module-scoped
# state and breaking command resolution in ways that only show up at
# runtime. Load order belongs to one place, not nine.
$script:ScriptExt = @('.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.py', '.sh', '.reg', '.lnk')
$script:ExecExt = @('.exe', '.dll', '.msi', '.msp', '.scr', '.sys', '.com', '.pif', '.cpl', '.ocx', '.jar', '.appx', '.msix')
$script:ArchiveExt = @('.zip', '.7z', '.rar', '.gz', '.tar', '.cab', '.iso', '.img', '.vhd', '.vhdx')
$script:DocExt = @('.doc', '.docm', '.dot', '.dotm', '.xls', '.xlsm', '.xlt', '.xltm', '.ppt', '.pptm', '.rtf', '.pdf', '.docx', '.xlsx', '.pptx')

function Get-NGFileType {
    <#
        Identifies type by magic bytes. Extension is attacker-controlled - the
        classic trick is invoice.pdf.exe, or an .exe renamed .txt that a wrapper
        later executes - so provenance decisions must not rest on it.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $fs = [IO.File]::OpenRead($Path)
        $buf = New-Object byte[] 16
        $read = $fs.Read($buf, 0, 16)
        $fs.Close()
        if ($read -lt 2) { return 'empty or truncated' }

        $hex = ([BitConverter]::ToString($buf[0..7]) -replace '-', '')
        $ascii = -join ($buf[0..7] | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } })

        if ($hex.StartsWith('4D5A')) { return 'PE executable (EXE/DLL/SYS)' }
        if ($hex.StartsWith('504B0304')) { return 'ZIP container (also DOCX/XLSX/JAR/APPX)' }
        if ($hex.StartsWith('377ABCAF271C')) { return '7-Zip archive' }
        if ($hex.StartsWith('52617221')) { return 'RAR archive' }
        if ($hex.StartsWith('25504446')) { return 'PDF document' }
        if ($hex.StartsWith('D0CF11E0')) { return 'Legacy OLE2 (DOC/XLS/MSI)' }
        if ($hex.StartsWith('4D534346')) { return 'Microsoft Cabinet' }
        if ($hex.StartsWith('1F8B')) { return 'GZIP' }
        if ($hex.StartsWith('7B5C7274')) { return 'RTF document' }
        if ($hex.StartsWith('4C000000')) { return 'Windows shortcut (LNK)' }
        if ($hex.StartsWith('CD001')) { return 'ISO image' }
        return "unknown (magic: $ascii / $($hex.Substring(0,[Math]::Min(16,$hex.Length))))"
    }
    catch { "unreadable: $($_.Exception.Message)" }
}

function Get-NGFileEntropy {
    <#
        Shannon entropy over the file bytes. Near 8.0 means the content is
        compressed or encrypted; for a plain EXE that usually indicates packing,
        which is common in malware and rare in legitimately distributed binaries.
        Archives are legitimately high-entropy, so this only informs EXE scoring.
    #>
    param([Parameter(Mandatory = $true)][string]$Path, [int]$MaxBytes = 2097152)
    try {
        $fs = [IO.File]::OpenRead($Path)
        $len = [Math]::Min($fs.Length, $MaxBytes)
        if ($len -eq 0) { $fs.Close(); return 0 }
        $buf = New-Object byte[] $len
        [void]$fs.Read($buf, 0, $len)
        $fs.Close()

        $freq = New-Object int[] 256
        foreach ($b in $buf) { $freq[$b]++ }
        $entropy = 0.0
        foreach ($count in $freq) {
            if ($count -eq 0) { continue }
            $p = $count / $len
            $entropy -= $p * [Math]::Log($p, 2)
        }
        [math]::Round($entropy, 3)
    }
    catch { -1 }
}

function Get-NGMarkOfTheWeb {
    <#
        Reads the Zone.Identifier alternate data stream. Windows writes this when a
        file arrives from the internet, and on modern builds it records the actual
        source URL - which is often the single most useful fact about a file.
        A missing MOTW on something that should have one means it was unblocked,
        extracted from an archive that stripped it, or delivered via a container
        (ISO/IMG/VHD) specifically chosen to evade this marking.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    $o = [ordered]@{ hasMotw = $false; zoneId = $null; referrerUrl = $null; hostUrl = $null; zoneName = 'none' }
    try {
        $raw = Get-Content -LiteralPath $Path -Stream 'Zone.Identifier' -Raw -ErrorAction Stop
        $o.hasMotw = $true
        foreach ($line in ($raw -split "`r?`n")) {
            if ($line -match '^\s*ZoneId\s*=\s*(\d+)') { $o.zoneId = [int]$Matches[1] }
            elseif ($line -match '^\s*ReferrerUrl\s*=\s*(.+)$') { $o.referrerUrl = $Matches[1].Trim() }
            elseif ($line -match '^\s*HostUrl\s*=\s*(.+)$') { $o.hostUrl = $Matches[1].Trim() }
        }
        $o.zoneName = switch ($o.zoneId) {
            0 { 'Local machine' }
            1 { 'Local intranet' }
            2 { 'Trusted sites' }
            3 { 'Internet' }
            4 { 'Restricted sites' }
            default { "unknown ($($o.zoneId))" }
        }
    }
    catch { }
    [pscustomobject]$o
}

function Get-NGVirusTotalReputation {
    <#
        HASH LOOKUP ONLY. Sends a SHA256, never file contents, so nothing about
        the file's data leaves the machine. A 404 means VirusTotal has never seen
        this hash, which for a widely-distributed installer is itself suspicious
        and for a freshly-built private binary is completely normal.
    #>
    param([Parameter(Mandatory = $true)][string]$Sha256)
    $key = Get-NGSecret -Name 'VirusTotalApiKey' -AsPlainText
    if ([string]::IsNullOrWhiteSpace($key)) {
        return [pscustomobject]@{ checked = $false; reason = 'no API key configured' }
    }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Sha256" `
            -Headers @{ 'x-apikey' = $key } -TimeoutSec 25 -ErrorAction Stop
        $stats = $r.data.attributes.last_analysis_stats
        [pscustomobject]@{
            checked      = $true
            known        = $true
            malicious    = [int]$stats.malicious
            suspicious   = [int]$stats.suspicious
            harmless     = [int]$stats.harmless
            undetected   = [int]$stats.undetected
            totalEngines = ([int]$stats.malicious + [int]$stats.suspicious + [int]$stats.harmless + [int]$stats.undetected)
            reputation   = [int]$r.data.attributes.reputation
            firstSeen    = $r.data.attributes.first_submission_date
            names        = @($r.data.attributes.names | Select-Object -First 5)
            threatLabel  = [string]$r.data.attributes.popular_threat_classification.suggested_threat_label
        }
    }
    catch {
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($status -eq 404) { return [pscustomobject]@{ checked = $true; known = $false; reason = 'hash unknown to VirusTotal' } }
        if ($status -eq 429) { return [pscustomobject]@{ checked = $false; reason = 'VirusTotal rate limit (4/min on the free tier)' } }
        [pscustomobject]@{ checked = $false; reason = $_.Exception.Message }
    }
}

function Get-NGStaticTriage {
    <# Content inspection: strings, URLs, LOLBin patterns, macros. #>
    param([Parameter(Mandatory = $true)][string]$Path)
    $ext = [IO.Path]::GetExtension($Path).ToLower()
    $o = [ordered]@{ indicators = @(); urls = @(); hasMacros = $false; suspiciousStrings = @() }

    # Printable strings from the first 4 MB - enough for headers and config blobs.
    $text = ''
    try {
        $fs = [IO.File]::OpenRead($Path)
        $len = [Math]::Min($fs.Length, 4194304)
        $buf = New-Object byte[] $len
        [void]$fs.Read($buf, 0, $len)
        $fs.Close()
        $sb = New-Object System.Text.StringBuilder
        foreach ($b in $buf) {
            if ($b -ge 32 -and $b -le 126) { [void]$sb.Append([char]$b) }
            else { [void]$sb.Append(' ') }
        }
        $text = $sb.ToString()
    }
    catch { }

    if ($text) {
        $o.urls = @([regex]::Matches($text, 'https?://[a-zA-Z0-9\.\-_/:%\?=&~\+]{6,180}') |
            ForEach-Object { $_.Value } | Sort-Object -Unique | Select-Object -First 30)

        $patterns = [ordered]@{
            'FromBase64String'                = 'base64 decoding of an embedded payload'
            '-enc\s|-EncodedCommand'          = 'encoded PowerShell command'
            'DownloadString|DownloadFile'     = 'remote code download'
            'Net\.WebClient|Invoke-WebRequest' = 'HTTP client usage'
            'AmsiUtils|amsiInitFailed|AmsiScanBuffer' = 'AMSI (antimalware scan interface) tampering'
            'VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection' = 'process injection primitives'
            'certutil.{0,40}(urlcache|decode)' = 'certutil abused to download or decode'
            'bitsadmin.{0,30}transfer'        = 'BITS used to fetch a payload'
            'vssadmin.{0,30}delete\s+shadows' = 'deletes volume shadow copies - ransomware behaviour'
            'wbadmin.{0,30}delete\s+catalog'  = 'destroys backup catalog - ransomware behaviour'
            'bcdedit.{0,40}recoveryenabled\s+no' = 'disables Windows recovery - ransomware behaviour'
            'Add-MpPreference.{0,40}Exclusion' = 'adds a Defender exclusion'
            'Set-MpPreference.{0,40}Disable'  = 'disables a Defender feature'
            'schtasks.{0,20}/create|New-ScheduledTask' = 'creates a scheduled task (persistence)'
            'CurrentVersion\\Run'             = 'writes a Run key (persistence)'
            'mshta|rundll32.{0,30}javascript' = 'LOLBin script execution'
            'wscript\.shell|WScript\.Shell'   = 'shell object instantiation'
            'Reflection\.Assembly.{0,20}Load' = 'in-memory .NET assembly loading'
            'nc\.exe|ncat|/dev/tcp'           = 'reverse shell tooling'
            'keylog|GetAsyncKeyState|SetWindowsHookEx' = 'keylogging primitives'
            'wallet\.dat|Local State|logins\.json' = 'credential or wallet file targeting'
        }
        foreach ($rx in $patterns.Keys) {
            if ($text -match $rx) { $o.suspiciousStrings += $patterns[$rx] }
        }
    }

    # Office macro detection: modern formats are ZIPs containing vbaProject.bin.
    if ($ext -in $script:DocExt) {
        try {
            if ($ext -in @('.docm', '.xlsm', '.pptm', '.dotm', '.xltm')) { $o.hasMacros = $true }
            $head = Get-Content -LiteralPath $Path -Encoding Byte -TotalCount 4 -ErrorAction Stop
            $hex = ([BitConverter]::ToString($head) -replace '-', '')
            if ($hex.StartsWith('504B0304')) {
                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                $zip = [IO.Compression.ZipFile]::OpenRead($Path)
                if (@($zip.Entries | Where-Object { $_.FullName -match 'vbaProject\.bin|vbaData\.xml' }).Count -gt 0) {
                    $o.hasMacros = $true
                }
                # An OOXML file carrying an external relationship can pull a remote
                # template - the Follina/template-injection delivery route.
                if (@($zip.Entries | Where-Object { $_.FullName -match '\.rels$' }).Count -gt 0) {
                    foreach ($e in @($zip.Entries | Where-Object { $_.FullName -match '\.rels$' })) {
                        $sr = New-Object IO.StreamReader($e.Open())
                        $rels = $sr.ReadToEnd(); $sr.Close()
                        if ($rels -match 'TargetMode="External".{0,200}(http|file)://') {
                            $o.indicators += 'OOXML external relationship (remote template injection vector)'
                        }
                    }
                }
                $zip.Dispose()
            }
            elseif ($hex.StartsWith('D0CF11E0')) {
                # Legacy OLE2: the VBA stream name appears in the raw container.
                if ($text -match 'VBA|_VBA_PROJECT|Macros') { $o.hasMacros = $true }
            }
        }
        catch { }
    }
    if ($o.hasMacros) { $o.indicators += 'contains VBA macros' }

    # A double extension is a social-engineering tell, not a technical one.
    $name = [IO.Path]::GetFileName($Path)
    if ($name -match '\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|mp4)\.(exe|scr|com|pif|bat|cmd|js|vbs|lnk)$') {
        $o.indicators += 'double extension disguising an executable as a document'
    }
    # RTL override hides the real extension in Explorer.
    if ($name -match "`u{202E}") { $o.indicators += 'right-to-left override character in filename (extension spoofing)' }

    [pscustomobject]$o
}

function Invoke-NGFileScan {
    <#
        Full pipeline for one file. Returns a verdict object; quarantine is a
        separate explicit step so scanning is always safe to run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$SkipAI,
        [switch]$SkipVirusTotal,
        [switch]$SkipDefender
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Not a file: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    $ext = $item.Extension.ToLower()

    Write-NGLog "Scanning $($item.Name) ($([math]::Round($item.Length/1KB,1)) KB)" -Agent scan

    $r = [ordered]@{
        path        = $item.FullName
        name        = $item.Name
        sizeBytes   = $item.Length
        created     = $item.CreationTimeUtc.ToString('o')
        extension   = $ext
        sha256      = (Get-NGFileHashSafe $item.FullName)
        fileType    = (Get-NGFileType $item.FullName)
        entropy     = (Get-NGFileEntropy $item.FullName)
        motw        = (Get-NGMarkOfTheWeb $item.FullName)
        signature   = $null
        antivirus   = $null
        virusTotal  = $null
        static      = (Get-NGStaticTriage $item.FullName)
        ai          = $null
        score       = 0
        verdict     = 'unknown'
        reasons     = @()
    }

    # ---- stage 3: signature. Delegated to the provider, because what counts as
    # "signed" differs per platform: Authenticode on Windows, package-manager
    # ownership on Linux. The provider sets supported=$false when the platform
    # has no real equivalent, and the scorer honours that.
    if ($ext -in $script:ExecExt -or $ext -in @('.ps1', '.psm1', '.cat') -or $ext -eq '') {
        if (Get-Command Get-NGSignatureStatus -ErrorAction SilentlyContinue) {
            $r.signature = Get-NGSignatureStatus -Path $item.FullName
        }
    }

    # ---- stage 4: Defender
    if (-not $SkipDefender) { $r.antivirus = Invoke-NGAntivirusScan -Path $item.FullName }

    # ---- stage 5: reputation
    if (-not $SkipVirusTotal -and $r.sha256) { $r.virusTotal = Get-NGVirusTotalReputation -Sha256 $r.sha256 }

    # ---- stage 7: AI source review for scripts and macro documents
    $isScript = ($ext -in $script:ScriptExt)
    if (-not $SkipAI -and $isScript -and $item.Length -lt 512000) {
        try {
            $content = Get-Content -LiteralPath $item.FullName -Raw -Encoding utf8 -ErrorAction Stop
            if ($content) {
                $r.ai = Invoke-NGScriptReview -Content $content -FileName $item.Name
            }
        }
        catch { Write-NGLog "Could not read $($item.Name) for AI review: $($_.Exception.Message)" -Level WARN -Agent scan }
    }

    # ---- stage 8: deterministic scoring
    # Higher is worse. Thresholds: >=60 quarantine, >=25 suspicious, else allow.
    $score = 0
    $reasons = New-Object System.Collections.Generic.List[psobject]

    function _add($points, $why) {
        $script:_s += $points
        $reasons.Add("[+$points] $why")
    }
    $script:_s = 0

    if ($r.antivirus -and $r.antivirus.ran -and $r.antivirus.clean -eq $false) {
        _add 100 "the local antivirus engine ($($r.antivirus.engine)) flagged this file"
    }
    $vt = $r.virusTotal
    if ($vt -and $vt.checked -and $vt.known) {
        if ([int]$vt.malicious -ge 5) { _add 100 "VirusTotal: $($vt.malicious)/$($vt.totalEngines) engines flag this ($($vt.threatLabel))" }
        elseif ([int]$vt.malicious -ge 1) { _add 45 "VirusTotal: $($vt.malicious)/$($vt.totalEngines) engines flag this" }
        elseif ([int]$vt.suspicious -ge 2) { _add 20 "VirusTotal: $($vt.suspicious) engines mark this suspicious" }
    }
    if ($r.ai) {
        switch ($r.ai.verdict) {
            'malicious' { _add 70 "AI source review: malicious ($($r.ai.confidence) confidence)" }
            'suspicious' { _add 30 "AI source review: suspicious ($($r.ai.confidence) confidence)" }
        }
        if ($r.ai.promptInjectionSuspected) {
            _add 25 'File contains text attempting to manipulate an AI analyser - deliberate evasion'
        }
    }
    # Unsigned or badly-signed executables.
    #
    # Only scored where the platform actually has code signing. On Linux almost
    # nothing is signed per-binary, so penalising "unsigned" there would add 15
    # points to every single file and make the threshold meaningless.
    if ($ext -in $script:ExecExt) {
        if ($r.signature -and $r.signature.supported) {
            if ($r.signature.status -eq 'NotSigned') { _add 15 'executable is not digitally signed' }
            elseif ($r.signature.status -ne 'Valid') { _add 30 "signature is present but not valid ($($r.signature.status))" }
        }
        elseif ($r.signature -and -not $r.signature.supported -and $r.signature.status -eq 'Unowned') {
            # Linux equivalent: a binary no package owns did not come from a repo.
            _add 10 'binary is not owned by any installed package'
        }
        if ($r.entropy -ge 7.2) { _add 12 "very high entropy ($($r.entropy)/8.0) - likely packed or encrypted" }
    }
    # Provenance.
    if ($r.motw.zoneId -eq 3) { _add 5 'downloaded from the internet zone' }
    if ($r.motw.zoneId -eq 4) { _add 15 'came from a restricted-sites zone' }
    if (-not $r.motw.hasMotw -and ($ext -in $script:ExecExt -or $isScript)) {
        _add 8 'no Mark-of-the-Web - may have been unblocked or delivered inside a container that strips it'
    }
    # Static indicators.
    $ransom = @($r.static.suspiciousStrings | Where-Object { $_ -match 'ransomware' })
    if ((Get-NGCount $ransom) -gt 0) { _add 55 "destructive/ransomware behaviour in strings: $($ransom -join '; ')" }
    $tamper = @($r.static.suspiciousStrings | Where-Object { $_ -match 'AMSI|Defender' })
    if ((Get-NGCount $tamper) -gt 0) { _add 40 "security-tampering strings: $($tamper -join '; ')" }
    $inject = @($r.static.suspiciousStrings | Where-Object { $_ -match 'injection|reverse shell|keylog' })
    if ((Get-NGCount $inject) -gt 0) { _add 30 "offensive tooling strings: $($inject -join '; ')" }
    $dl = @($r.static.suspiciousStrings | Where-Object { $_ -match 'download|base64|encoded' })
    if ((Get-NGCount $dl) -gt 0 -and $isScript) { _add 20 "script downloads or decodes a payload: $($dl -join '; ')" }
    foreach ($ind in @($r.static.indicators)) {
        if ($ind -match 'double extension|right-to-left') { _add 45 $ind }
        elseif ($ind -match 'external relationship') { _add 35 $ind }
        elseif ($ind -match 'VBA macros') { _add 20 $ind }
    }
    if ($ext -in @('.iso', '.img', '.vhd', '.vhdx') ) {
        _add 15 'disk-image container - a common way to deliver payloads without Mark-of-the-Web'
    }
    if ($ext -eq '.lnk') { _add 20 'shortcut file - frequently used to launch hidden commands' }

    $score = $script:_s
    Remove-Variable -Name _s -Scope Script -ErrorAction SilentlyContinue

    $r.score = $score
    $r.reasons = @($reasons)
    $r.verdict = if ($score -ge 60) { 'quarantine' }
    elseif ($score -ge 25) { 'suspicious' }
    else { 'allow' }

    $out = [pscustomobject]$r
    # Keep a durable record of every scan: useful for later hash lookups and for
    # the weekly report, and it means a verdict can be revisited after the fact.
    $evDir = Get-NGPath 'evidence'
    if (-not (Test-Path $evDir)) { New-Item -ItemType Directory -Path $evDir -Force | Out-Null }
    $evFile = Join-Path $evDir ("scan-{0}-{1}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ($item.BaseName -replace '[^\w\-]', '_'))
    ($out | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $evFile -Encoding utf8

    Write-NGLog "Verdict for $($item.Name): $($r.verdict) (score $score)" -Agent scan `
        -Level $(if ($r.verdict -eq 'quarantine') { 'ERROR' } elseif ($r.verdict -eq 'suspicious') { 'WARN' } else { 'INFO' })
    $out
}

function Move-NGToQuarantine {
    <#
        Neutralises a file rather than deleting it: renamed so it cannot execute,
        moved to an ACL-restricted folder, with a sidecar recording where it came
        from. Deleting destroys the evidence needed to work out how it arrived.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$ScanResult)

    $qDir = Get-NGPath 'quarantine'
    if (-not (Test-Path $qDir)) { New-Item -ItemType Directory -Path $qDir -Force | Out-Null }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safeName = "$stamp-$($ScanResult.name).quarantined"
    $dest = Join-Path $qDir $safeName
    try {
        Move-Item -LiteralPath $ScanResult.path -Destination $dest -Force -ErrorAction Stop
        ($ScanResult | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath "$dest.json" -Encoding utf8
        Protect-NGFile -Path $dest
        Write-NGLog "Quarantined to $dest" -Level WARN -Agent scan
        [pscustomobject]@{ quarantined = $true; destination = $dest }
    }
    catch {
        Write-NGLog "Quarantine FAILED for $($ScanResult.path): $($_.Exception.Message)" -Level ERROR -Agent scan
        [pscustomobject]@{ quarantined = $false; error = $_.Exception.Message }
    }
}

function ConvertTo-NGScanFinding {
    <# Turns a scan verdict into a finding for the alert pipeline. #>
    param([Parameter(Mandatory = $true)]$ScanResult, [switch]$Quarantined)

    $sev = switch ($ScanResult.verdict) {
        'quarantine' { 'Critical' }
        'suspicious' { 'High' }
        default { 'Info' }
    }
    $origin = 'unknown'
    if ($ScanResult.motw.hostUrl) { $origin = $ScanResult.motw.hostUrl }
    elseif ($ScanResult.motw.referrerUrl) { $origin = $ScanResult.motw.referrerUrl }

    $detail = @"
**File:** $($ScanResult.name)
**Type:** $($ScanResult.fileType)
**SHA256:** ``$($ScanResult.sha256)``
**Origin:** $origin (zone: $($ScanResult.motw.zoneName))
**Risk score:** $($ScanResult.score)

**Why:**
$((@($ScanResult.reasons) | ForEach-Object { "- $_" }) -join "`n")
"@
    if ($ScanResult.ai) {
        $detail += "`n`n**AI source review ($($ScanResult.ai.verdict), $($ScanResult.ai.confidence) confidence):** $($ScanResult.ai.summary)"
        if (@($ScanResult.ai.capabilities).Count -gt 0) {
            $detail += "`n**Observed capabilities:** " + (@($ScanResult.ai.capabilities) -join '; ')
        }
        if (@($ScanResult.ai.indicators).Count -gt 0) {
            $detail += "`n**Indicators:** " + ((@($ScanResult.ai.indicators) | Select-Object -First 8) -join ', ')
        }
    }
    if ($Quarantined) { $detail += "`n`n**Action taken:** moved to the NetGuard quarantine folder and renamed so it cannot execute." }

    New-NGFinding -Category 'Download' -Severity $sev -Agent 'scan' `
        -Title "$($ScanResult.verdict.ToUpper()): $($ScanResult.name)" `
        -Detail $detail `
        -Recommendation $(if ($ScanResult.verdict -eq 'quarantine') {
            'Do not restore it. If you believe it is a false positive, verify the SHA256 against the vendor''s published hash before doing anything else.'
        }
        else {
            'Review the reasons above. If you cannot account for how this file arrived, treat it as hostile.'
        }) `
        -Evidence @{
            sha256 = $ScanResult.sha256; score = $ScanResult.score
            origin = $origin; reasons = @($ScanResult.reasons)
        } `
        -FingerprintSeed "scan|$($ScanResult.sha256)"
}

Export-ModuleMember -Function *
