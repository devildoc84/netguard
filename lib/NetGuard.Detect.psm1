<#
    NetGuard.Detect - deterministic, cross-platform detection rules.

    Every function takes normalised collector output and returns findings. No
    network calls, no AI, no side effects beyond baseline updates. Keeping
    detection separate from collection means rules can be unit-tested against
    captured JSON, and it keeps the alerting decision out of the model's hands.

    PLATFORM NEUTRALITY. There is no OS branch in this file. Providers emit the
    normalised shapes documented in lib/NetGuard.Platform.psm1, so these rules
    work identically on Windows and Linux. Rules that genuinely cannot be
    expressed generically live in the provider's Find-NGPlatformPostureFindings.

    TRI-STATE DISCIPLINE. $true means confirmed enabled, $false means confirmed
    disabled, $null means could not read. Detectors test `-eq $false`, never
    `-not $x`, so unreadable data stays silent instead of raising a false alarm.

    BASELINE PHILOSOPHY. The FIRST run of any diff-based detector records the
    baseline silently rather than alerting on hundreds of pre-existing items.
    Drift from that point forward is what alerts. Get-NGBaseline returning $null
    is a "learn, do not alarm" signal, not an error.
#>

# Dependencies are loaded by Import-NGStack (lib/NetGuard.Platform.psm1),
# in order, exactly once. This module deliberately does NOT import its
# siblings: an Import-Module -Force from inside a module unloads and
# reloads the shared module graph mid-import, discarding module-scoped
# state and breaking command resolution in ways that only show up at
# runtime. Load order belongs to one place, not nine.
# Ports that materially change exposure when reachable from a real network.
$script:NGRiskyPorts = @{
    21    = @{ name = 'FTP';           sev = 'High';     why = 'Cleartext credentials and file transfer.' }
    22    = @{ name = 'SSH';           sev = 'Low';      why = 'Normal on Linux; should be key-only and never exposed to the internet with password auth.' }
    23    = @{ name = 'Telnet';        sev = 'Critical'; why = 'Cleartext remote shell. No legitimate modern use.' }
    69    = @{ name = 'TFTP';          sev = 'High';     why = 'Unauthenticated file transfer, common malware staging.' }
    135   = @{ name = 'RPC endpoint';  sev = 'Low';      why = 'Normal on Windows, but must never be internet-reachable.' }
    139   = @{ name = 'NetBIOS';       sev = 'Medium';   why = 'Legacy SMB/NetBIOS. Should be disabled on modern networks.' }
    445   = @{ name = 'SMB';           sev = 'Low';      why = 'Normal on a LAN; catastrophic if exposed to the internet.' }
    512   = @{ name = 'rexec';         sev = 'Critical'; why = 'Legacy r-service. Cleartext and trivially abused.' }
    513   = @{ name = 'rlogin';        sev = 'Critical'; why = 'Legacy r-service. Cleartext and trivially abused.' }
    514   = @{ name = 'rsh';           sev = 'Critical'; why = 'Legacy r-service. Cleartext and trivially abused.' }
    1433  = @{ name = 'MSSQL';         sev = 'High';     why = 'Database directly exposed.' }
    1723  = @{ name = 'PPTP VPN';      sev = 'High';     why = 'PPTP/MS-CHAPv2 is cryptographically broken and crackable offline.' }
    2049  = @{ name = 'NFS';           sev = 'High';     why = 'Network file system, historically weak authentication.' }
    2375  = @{ name = 'Docker API';    sev = 'Critical'; why = 'An unauthenticated Docker socket over TCP is root-equivalent remote code execution.' }
    2376  = @{ name = 'Docker TLS';    sev = 'High';     why = 'Docker API over TLS; still root-equivalent if certificates leak.' }
    3306  = @{ name = 'MySQL';         sev = 'High';     why = 'Database directly exposed.' }
    3389  = @{ name = 'RDP';           sev = 'High';     why = 'Primary ransomware entry vector when reachable.' }
    4899  = @{ name = 'Radmin';        sev = 'High';     why = 'Remote control service.' }
    5432  = @{ name = 'PostgreSQL';    sev = 'High';     why = 'Database directly exposed.' }
    5555  = @{ name = 'ADB / misc';    sev = 'Medium';   why = 'Android Debug Bridge allows unauthenticated device control.' }
    5900  = @{ name = 'VNC';           sev = 'High';     why = 'Often unauthenticated or weakly authenticated remote control.' }
    5985  = @{ name = 'WinRM HTTP';    sev = 'Medium';   why = 'Remote PowerShell. Acceptable on a trusted LAN, never externally.' }
    5986  = @{ name = 'WinRM HTTPS';   sev = 'Low';      why = 'Encrypted remote PowerShell.' }
    6379  = @{ name = 'Redis';         sev = 'Critical'; why = 'Redis defaults to no authentication and allows trivial RCE.' }
    8500  = @{ name = 'Consul';        sev = 'High';     why = 'Service mesh API, frequently unauthenticated.' }
    9200  = @{ name = 'Elasticsearch'; sev = 'High';     why = 'Frequently unauthenticated.' }
    10250 = @{ name = 'Kubelet';       sev = 'Critical'; why = 'The kubelet API can expose container exec without authentication.' }
    11211 = @{ name = 'Memcached';     sev = 'High';     why = 'Unauthenticated and a major UDP amplification source.' }
    27017 = @{ name = 'MongoDB';       sev = 'Critical'; why = 'Historically unauthenticated by default.' }
}

# ============================================================ POSTURE ========

function Find-NGPostureFindings {
    <#
        Cross-platform posture rules over the normalised contract, then delegates
        to the provider for OS-specific rules. A provider that fills the
        normalised fields gets all of this for free.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Posture)
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'posture'

    # ---------------- antivirus / endpoint protection
    $av = $Posture.antivirus
    if ($av) {
        if (-not $av.readable) {
            $f.Add((New-NGFinding -Category 'Antivirus' -Severity 'High' -Agent $agentId `
                        -Title 'Antivirus status could not be read' `
                        -Detail 'The endpoint protection status query returned nothing. Either the service is not running, another product has displaced it, or the interface is damaged. All three are worth knowing, and none should be reported as healthy.' `
                        -Recommendation 'Query the antivirus status manually on this host. If it errors, check that the service is running.' `
                        -Evidence $av -FingerprintSeed 'av-unreadable'))
        }
        elseif ($av.present -eq $false) {
            $f.Add((New-NGFinding -Category 'Antivirus' -Severity 'High' -Agent $agentId `
                        -Title 'No antivirus or anti-malware engine detected' `
                        -Detail 'Nothing is scanning files on this host. On Linux this is common, but it means downloads are only checked by the static analysis in the scan pipeline.' `
                        -Recommendation 'Install an on-demand scanner (ClamAV on Linux) so the download pipeline gains a signature stage.' `
                        -Evidence $av -FingerprintSeed 'av-absent'))
        }
        if ($av.realtimeEnabled -eq $false) {
            $f.Add((New-NGFinding -Category 'Antivirus' -Severity 'Critical' -Agent $agentId `
                        -Title 'Antivirus real-time protection is OFF' `
                        -Detail 'Real-time protection is the component that blocks execution of known-bad code. With it off, on-demand scans only find what has already landed.' `
                        -Recommendation 'Re-enable real-time protection, and check whether policy or another product turned it off.' `
                        -Evidence $av -FingerprintSeed 'av-rtp-off'))
        }
        if ($av.tamperProtected -eq $false) {
            $f.Add((New-NGFinding -Category 'Antivirus' -Severity 'High' -Agent $agentId `
                        -Title 'Antivirus tamper protection is not active' `
                        -Detail 'Without tamper protection, any process with administrative rights can silently disable the scanner - the first thing most modern malware attempts.' `
                        -Recommendation 'Enable tamper protection in the security product own interface.' `
                        -Evidence $av -FingerprintSeed 'av-tamper-off'))
        }
        $sigAge = [int]$av.signatureAgeDays
        if ($sigAge -ge 3 -and $sigAge -ne -1) {
            $sev = if ($sigAge -ge 7) { 'High' } else { 'Medium' }
            $f.Add((New-NGFinding -Category 'Antivirus' -Severity $sev -Agent $agentId `
                        -Title "Antivirus signatures are $sigAge days old" `
                        -Detail 'Stale signatures mean no coverage for anything discovered since that date.' `
                        -Recommendation 'Run a signature update, and investigate why the automatic update is not working.' `
                        -Evidence $av -FingerprintSeed 'av-sig-stale'))
        }
        $scanAge = [int]$av.lastScanAgeDays
        if ($scanAge -ge 14 -and $scanAge -ne -1) {
            $f.Add((New-NGFinding -Category 'Antivirus' -Severity 'Low' -Agent $agentId `
                        -Title "No antivirus scan in $scanAge days" `
                        -Detail 'Scheduled scans catch dormant files that real-time protection saw before a signature existed.' `
                        -Recommendation 'Run a scan and confirm the scheduled scan job is enabled.' `
                        -Evidence $av -FingerprintSeed 'av-scan-stale'))
        }
    }

    # ---------------- firewall
    foreach ($fw in @($Posture.firewall)) {
        if (-not $fw) { continue }
        $label = if ($fw.profile) { $fw.profile } else { 'default' }
        if ($fw.enabled -eq $false) {
            $f.Add((New-NGFinding -Category 'Firewall' -Severity 'Critical' -Agent $agentId `
                        -Title "Host firewall is disabled ($label)" `
                        -Detail 'Every listening service on this host is reachable from the attached network.' `
                        -Recommendation 'Enable the firewall for this profile.' `
                        -Evidence $fw -FingerprintSeed "fw-disabled-$label"))
        }
        if ($fw.defaultInbound -and $fw.defaultInbound -ne 'Block') {
            $f.Add((New-NGFinding -Category 'Firewall' -Severity 'Medium' -Agent $agentId `
                        -Title "Firewall default inbound policy on $label is '$($fw.defaultInbound)'" `
                        -Detail 'An implicit default can change under a policy refresh or a third-party tool without anyone noticing. A stated deny policy cannot.' `
                        -Recommendation 'Set the default inbound policy explicitly to Block or DROP.' `
                        -Evidence $fw -FingerprintSeed "fw-inbound-$label"))
        }
        if ($fw.logging -eq $false) {
            $f.Add((New-NGFinding -Category 'Firewall' -Severity 'Medium' -Agent $agentId `
                        -Title "Firewall is not logging dropped packets ($label)" `
                        -Detail 'Without dropped-packet logs there is no record of scanning or probing against this host, so the monitoring has a blind spot directly at the network edge.' `
                        -Recommendation 'Enable drop logging with a capped log size.' `
                        -Evidence $fw -FingerprintSeed "fw-nolog-$label"))
        }
    }

    # ---------------- disk encryption
    foreach ($de in @($Posture.diskEncryption)) {
        if (-not $de -or -not $de.readable) { continue }
        if ($de.status -notin 'On', 'Encrypted', 'active') {
            $f.Add((New-NGFinding -Category 'Platform' -Severity 'High' -Agent $agentId `
                        -Title "Disk encryption is not protecting $($de.mount)" `
                        -Detail 'Unencrypted at rest: anyone with brief physical access can read every file, extract credentials, and plant persistence by booting another OS.' `
                        -Recommendation 'Enable full-disk encryption and store the recovery key somewhere that is not this machine.' `
                        -Evidence $de -FingerprintSeed "disk-unencrypted-$($de.mount)"))
        }
    }

    # ---------------- secure boot
    if ($Posture.secureBoot -eq $false) {
        $f.Add((New-NGFinding -Category 'Platform' -Severity 'High' -Agent $agentId `
                    -Title 'Secure Boot is disabled' `
                    -Detail 'Without Secure Boot a bootkit can load before the OS and before any security software gets to run.' `
                    -Recommendation 'Enable Secure Boot in UEFI firmware settings. Confirm the disk is GPT and boot mode is UEFI first, or the machine will not boot.' `
                    -Evidence @{ secureBoot = $false } -FingerprintSeed 'secureboot-off'))
    }

    # ---------------- patching
    $pt = $Posture.patching
    if ($pt -and $pt.readable -and $null -ne $pt.daysSinceLastUpdate) {
        $days = [int]$pt.daysSinceLastUpdate
        if ($days -gt 45) {
            $sev = if ($days -gt 90) { 'High' } else { 'Medium' }
            $f.Add((New-NGFinding -Category 'Patching' -Severity $sev -Agent $agentId `
                        -Title "No security update installed in $days days" `
                        -Detail 'Monthly patches close vulnerabilities that are public and being exploited within days of release.' `
                        -Recommendation 'Apply pending updates and confirm the update service is enabled.' `
                        -Evidence $pt -FingerprintSeed 'patch-stale'))
        }
    }
    if ($pt -and $pt.autoUpdate -eq $false) {
        $f.Add((New-NGFinding -Category 'Patching' -Severity 'High' -Agent $agentId `
                    -Title 'Automatic security updates are disabled' `
                    -Detail 'This host will not receive security patches on its own. Disabling the update service is also a known malware persistence tactic.' `
                    -Recommendation 'Re-enable automatic security updates.' `
                    -Evidence $pt -FingerprintSeed 'autoupdate-off'))
    }
    if ($pt -and $null -ne $pt.pendingSecurity -and [int]$pt.pendingSecurity -gt 0) {
        $n = [int]$pt.pendingSecurity
        $sev = if ($n -ge 20) { 'High' } else { 'Medium' }
        $f.Add((New-NGFinding -Category 'Patching' -Severity $sev -Agent $agentId `
                    -Title "$n security update(s) pending installation" `
                    -Detail 'These are published fixes for known vulnerabilities that are not yet applied on this host.' `
                    -Recommendation 'Install the pending security updates.' `
                    -Evidence $pt -FingerprintSeed 'pending-security-updates'))
    }

    # ---------------- logging
    $lg = $Posture.logging
    if ($lg) {
        if ($lg.commandAuditing -eq $false) {
            $f.Add((New-NGFinding -Category 'Logging' -Severity 'Medium' -Agent $agentId `
                        -Title 'Process and command auditing is not enabled' `
                        -Detail 'Without command-line auditing you learn that a process started but not what it was told to do, which is usually the only part that matters.' `
                        -Recommendation 'Enable process creation auditing including command lines. The Tier 1 hardening script does this.' `
                        -Evidence $lg -FingerprintSeed 'cmdline-audit-off'))
        }
        if ($lg.scriptLogging -eq $false) {
            $f.Add((New-NGFinding -Category 'Logging' -Severity 'Medium' -Agent $agentId `
                        -Title 'Shell and script execution logging is not enabled' `
                        -Detail 'Without it, NetGuard can see that an interpreter ran but not the code it executed - and obfuscated one-liners are the most common delivery method.' `
                        -Recommendation 'Enable script or command logging. The Tier 1 hardening script does this.' `
                        -Evidence $lg -FingerprintSeed 'script-logging-off'))
        }
    }

    # ---------------- uptime as a pending-reboot proxy
    if ($null -ne $Posture.uptimeDays -and [double]$Posture.uptimeDays -gt 30) {
        $f.Add((New-NGFinding -Category 'Patching' -Severity 'Low' -Agent $agentId `
                    -Title "Uptime is $($Posture.uptimeDays) days" `
                    -Detail 'Many kernel and credential-subsystem patches only take effect after a reboot, so a long uptime often means patches are installed but not active.' `
                    -Recommendation 'Reboot when convenient.' `
                    -Evidence @{ uptimeDays = $Posture.uptimeDays } -FingerprintSeed 'uptime-long'))
    }

    # ---------------- provider-specific rules
    #
    # ASSIGN first, then iterate. This is fussier than it looks.
    #
    # The finder returns a comma-wrapped array (`, @($f)`) so a 0- or 1-element
    # result survives without collapsing to $null or a scalar. That wrapper
    # changes how every calling form behaves:
    #
    #   @(Find-...)              -> ONE element that is itself the array (wrong)
    #   Find-... | ForEach-Object -> ONE pipeline object, the whole array (wrong)
    #   $x = Find-...            -> the array itself, ready to iterate (right)
    #
    # Both wrong forms silently added six real findings as a single unusable
    # object, which reads downstream as "the platform had nothing to report".
    if (Get-Command Find-NGPlatformPostureFindings -ErrorAction SilentlyContinue) {
        $platformFindings = Find-NGPlatformPostureFindings -Posture $Posture
        foreach ($pf in $platformFindings) {
            if ($pf) { $f.Add($pf) }
        }
    }

    , @($f)
}

# ============================================================== PORTS ========

function Find-NGPortFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()]$Ports)
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'ports'

    # Rule 1: inherently risky ports genuinely reachable from the network.
    # Grouped by protocol+port+process, not per address: a service bound to six
    # virtual-switch addresses is one issue, not six alerts.
    $reachable = @($Ports | Where-Object { $_.reachable })
    $groups = $reachable | Where-Object { $script:NGRiskyPorts.ContainsKey([int]$_.port) } |
        Group-Object { "$($_.protocol)|$($_.port)|$($_.processName)" }

    foreach ($g in $groups) {
        $first = $g.Group[0]
        $info = $script:NGRiskyPorts[[int]$first.port]
        $addrs = @($g.Group | ForEach-Object { $_.localAddress }) | Sort-Object -Unique
        $onWildcard = (Get-NGCount @($g.Group | Where-Object { $_.scope -eq 'any' })) -gt 0

        # A wildcard bind is worse than a bind to one known interface, because it
        # follows the machine onto every future network including untrusted Wi-Fi.
        $sev = $info.sev
        if (-not $onWildcard) {
            if ($sev -eq 'Critical') { $sev = 'High' }
            elseif ($sev -eq 'High') { $sev = 'Medium' }
        }

        $bindDesc = if ($onWildcard) { 'all interfaces (0.0.0.0 / ::)' } else { $addrs -join ', ' }
        $f.Add((New-NGFinding -Category 'Exposure' -Severity $sev -Agent $agentId `
                    -Title "$($info.name) reachable on $($first.protocol)/$($first.port) via $($first.processName)" `
                    -Detail ("$($info.why)`n`nBound to: $bindDesc`nOwning process: $($first.processName) " +
                             "(PID $($first.processId))`nImage: $($first.processPath)") `
                    -Recommendation 'If this service is not needed, stop and disable it. If it is, scope a firewall rule to specific source addresses instead of leaving it open, and make sure it is not port-forwarded at the router.' `
                    -Evidence @{ addresses = $addrs; wildcardBind = $onWildcard; listeners = @($g.Group) } `
                    -FingerprintSeed "riskyport|$($first.protocol)|$($first.port)|$($first.processName)"))
    }

    # Rule 2: drift against the baseline - a NEW listener is the interesting event.
    #
    # Two filters make this usable rather than a firehose:
    #   * Ephemeral ports (>=49152) are excluded. They churn on every run and
    #     produced 80 Medium findings in a single cycle during testing, which is
    #     exactly how a monitoring system gets muted.
    #   * Identity is protocol+port+process, NOT the bind address.
    $stable = @($Ports | Where-Object { $_.reachable -and [int]$_.port -lt 49152 } |
        Group-Object { "$($_.protocol)|$($_.port)|$($_.processName)" } | ForEach-Object {
            $first = $_.Group[0]
            [pscustomobject]@{
                key          = $_.Name
                protocol     = $first.protocol
                port         = $first.port
                processName  = $first.processName
                processPath  = $first.processPath
                addresses    = (@($_.Group | ForEach-Object { $_.localAddress }) | Sort-Object -Unique) -join ','
                wildcardBind = ((Get-NGCount @($_.Group | Where-Object { $_.scope -eq 'any' })) -gt 0)
            }
        })

    $baseline = Get-NGBaseline -Name 'ports'
    if ($null -eq $baseline) {
        Set-NGBaseline -Name 'ports' -Value $stable
        Write-NGLog "Recorded initial port baseline ($(Get-NGCount $stable) services); not alerting on pre-existing state." -Agent $agentId
    }
    else {
        $diff = Compare-NGSnapshot -Baseline $baseline -Current $stable -Key 'key' -CompareProperties @('processPath')
        foreach ($n in @($diff.Added)) {
            $f.Add((New-NGFinding -Category 'Exposure' -Severity 'Medium' -Agent $agentId `
                        -Title "New network listener: $($n.protocol)/$($n.port) opened by $($n.processName)" `
                        -Detail ("A service began listening on $($n.addresses) that was not present at the last baseline.`nImage: $($n.processPath)") `
                        -Recommendation 'Confirm you installed or started this. If unexpected, identify the binary and check its signature before anything else.' `
                        -Evidence $n -FingerprintSeed "newport|$($n.key)"))
        }
        foreach ($c in @($diff.Changed)) {
            $f.Add((New-NGFinding -Category 'Exposure' -Severity 'High' -Agent $agentId `
                        -Title "Binary behind $($c.current.protocol)/$($c.current.port) changed" `
                        -Detail ("The image serving this port changed.`nWas: $($c.deltas[0].from)`nNow: $($c.deltas[0].to)`n`nA legitimate update looks like this; so does service hijacking.") `
                        -Recommendation 'Verify the new binary path and signature.' `
                        -Evidence $c -FingerprintSeed "portowner|$($c.key)|$($c.current.processPath)"))
        }
        Set-NGBaseline -Name 'ports' -Value $stable
    }
    , @($f)
}

# ================================================================ LAN ========

function Find-NGLanFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()]$Devices)
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'discovery'
    if ((Get-NGCount $Devices) -eq 0) { return , @() }

    $baseline = Get-NGBaseline -Name 'lan-devices'
    if ($null -eq $baseline) {
        Set-NGBaseline -Name 'lan-devices' -Value $Devices
        Write-NGLog "Recorded initial LAN baseline ($(Get-NGCount $Devices) devices); not alerting on pre-existing devices." -Agent $agentId
        return , @()
    }

    $diff = Compare-NGSnapshot -Baseline $baseline -Current @($Devices) -Key 'mac' -CompareProperties @('ipAddress', 'hostName')

    foreach ($n in @($diff.Added)) {
        # A device whose vendor is unknown AND has no resolvable hostname is the
        # least accountable thing on a network, so it scores higher.
        $sev = 'Medium'
        if ($n.vendor -like 'unknown*' -and -not $n.hostName) { $sev = 'High' }
        $hostLabel = if ($n.hostName) { $n.hostName } else { 'not resolvable' }
        $f.Add((New-NGFinding -Category 'Network' -Severity $sev -Agent $agentId `
                    -Title "New device on the LAN: $($n.ipAddress) [$($n.vendor)]" `
                    -Detail "MAC $($n.mac), hostname $hostLabel, vendor $($n.vendor). This MAC was not in the approved device baseline." `
                    -Recommendation 'Identify it. If it is yours, run tools/Approve-NGDevice.ps1 -Mac to add it to the baseline. If not, change the Wi-Fi passphrase, check the router client list, and consider an isolated IoT network.' `
                    -Evidence $n -FingerprintSeed "newdevice|$($n.mac)"))
    }

    # Gateway MAC changing is a strong ARP-spoofing / router-swap indicator.
    foreach ($c in @($diff.Changed)) {
        if ($c.current.isGateway) {
            $f.Add((New-NGFinding -Category 'Network' -Severity 'High' -Agent $agentId `
                        -Title "Default gateway identity changed ($($c.current.ipAddress))" `
                        -Detail 'The MAC-to-IP mapping for the default gateway changed. Benign causes: a new router, or ISP hardware replacement. Malicious cause: ARP spoofing to man-in-the-middle all of your traffic.' `
                        -Recommendation 'Compare the MAC against the label on your router. If it does not match, disconnect from the network and investigate from a known-good device.' `
                        -Evidence $c -FingerprintSeed "gateway-change|$($c.current.mac)"))
        }
    }

    Set-NGBaseline -Name 'lan-devices' -Value $Devices
    , @($f)
}

# ========================================================= PERSISTENCE =======

function Find-NGAutorunFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()]$Autoruns)
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'persistence'

    # Commands that are almost never legitimate in an autostart entry. Patterns
    # cover both Windows and Unix conventions so the rule stays shared.
    $badPatterns = @(
        @{ rx = 'FromBase64String|-enc\s|-encodedcommand|base64\s+-d|base64\s+--decode'; why = 'decodes a base64 command payload' }
        @{ rx = 'DownloadString|DownloadFile|Invoke-WebRequest|curl\s+[^|]*\|\s*(sh|bash|iex|powershell)|wget\s+[^|]*\|\s*(sh|bash)'; why = 'downloads and executes remote code' }
        @{ rx = '\bmshta\b.*http|\brundll32\b.*javascript:|\bregsvr32\b.*/i:http'; why = 'uses a LOLBin to execute remote script' }
        @{ rx = '-w\s+hidden|-windowstyle\s+hidden'; why = 'deliberately hides its window' }
        @{ rx = 'AppData.{0,12}Temp|Users.{0,3}Public|/tmp/|/dev/shm/|/var/tmp/'; why = 'executes from a world-writable temporary location' }
        @{ rx = '\bcertutil\b.*-(urlcache|decode)'; why = 'abuses certutil for download or decoding' }
        @{ rx = '\bbitsadmin\b.*/transfer'; why = 'uses BITS to fetch a payload' }
        @{ rx = 'nc\s+-[a-z]*e|ncat.*--exec|/dev/tcp/|bash\s+-i\s*>&'; why = 'matches a reverse shell pattern' }
        @{ rx = 'chattr\s+\+i|history\s+-c|unset\s+HISTFILE'; why = 'performs anti-forensics or log tampering' }
        @{ rx = 'ld\.so\.preload'; why = 'hijacks every dynamically linked binary via LD_PRELOAD' }
    )

    foreach ($entry in @($Autoruns)) {
        if (-not $entry -or -not $entry.command) { continue }
        foreach ($bp in $badPatterns) {
            if ($entry.command -match $bp.rx) {
                $f.Add((New-NGFinding -Category 'Persistence' -Severity 'High' -Agent $agentId `
                            -Title "Suspicious autostart entry: $($entry.name)" `
                            -Detail "A $($entry.type) autostart entry $($bp.why). Location: $($entry.location). Command: $($entry.command)" `
                            -Recommendation 'Do not delete it yet - capture the command and any referenced file first, hash the file, and scan it. Then remove the entry and the payload together.' `
                            -Evidence $entry -FingerprintSeed "badautorun|$($entry.key)"))
                break
            }
        }
    }

    $baseline = Get-NGBaseline -Name 'autoruns'
    if ($null -eq $baseline) {
        Set-NGBaseline -Name 'autoruns' -Value $Autoruns
        Write-NGLog "Recorded initial autoruns baseline ($(Get-NGCount $Autoruns) entries)." -Agent $agentId
    }
    else {
        $diff = Compare-NGSnapshot -Baseline $baseline -Current @($Autoruns) -Key 'key' -CompareProperties @('command')
        foreach ($n in @($diff.Added)) {
            # Weight by type: fileless and user-writable persistence is higher
            # signal than a new unit installed by a package manager.
            $sev = switch ($n.type) {
                'WmiSubscription' { 'High' }
                'ShellProfile' { 'High' }
                'LdPreload' { 'Critical' }
                'RegistryRun' { 'Medium' }
                'StartupFolder' { 'Medium' }
                'Cron' { 'Medium' }
                'SystemdTimer' { 'Medium' }
                'SystemdUserUnit' { 'Medium' }
                'RcLocal' { 'Medium' }
                default { 'Low' }
            }
            $f.Add((New-NGFinding -Category 'Persistence' -Severity $sev -Agent $agentId `
                        -Title "New $($n.type) autostart: $($n.name)" `
                        -Detail "Command: $($n.command)`nLocation: $($n.location)" `
                        -Recommendation 'Match this against software you installed recently. Unmatched autostart entries are how malware survives reboots.' `
                        -Evidence $n -FingerprintSeed "newautorun|$($n.key)"))
        }
        foreach ($c in @($diff.Changed)) {
            $f.Add((New-NGFinding -Category 'Persistence' -Severity 'Medium' -Agent $agentId `
                        -Title "Autostart command changed: $($c.current.name)" `
                        -Detail ("Was: $($c.deltas[0].from)`nNow: $($c.deltas[0].to)") `
                        -Recommendation 'Legitimate updates rewrite these; so does hijacking. Verify the new target binary.' `
                        -Evidence $c -FingerprintSeed "chgautorun|$($c.key)"))
        }
        Set-NGBaseline -Name 'autoruns' -Value $Autoruns
    }
    , @($f)
}

# ============================================================ ACCOUNTS =======

function Find-NGAccountFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Accounts)
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'accounts'

    foreach ($u in @($Accounts.users)) {
        if (-not $u) { continue }
        if ($u.enabled -eq $true -and $u.passwordRequired -eq $false) {
            $f.Add((New-NGFinding -Category 'Accounts' -Severity 'High' -Agent $agentId `
                        -Title "Enabled account '$($u.name)' has no password requirement" `
                        -Detail 'A passwordless enabled account can be used for local or network logon depending on policy.' `
                        -Recommendation 'Set a password or disable the account.' `
                        -Evidence $u -FingerprintSeed "nopass|$($u.key)"))
        }
        if ($u.enabled -eq $true -and $u.isBuiltinAdmin -eq $true) {
            $f.Add((New-NGFinding -Category 'Accounts' -Severity 'Medium' -Agent $agentId `
                        -Title "The built-in administrator account '$($u.name)' is enabled" `
                        -Detail 'The built-in administrator has a well-known identifier, is often exempt from lockout policy, and is a preferred brute-force and lateral-movement target.' `
                        -Recommendation 'Disable direct login to it and use a named administrative account instead.' `
                        -Evidence $u -FingerprintSeed 'builtin-admin-enabled'))
        }
    }

    $baseline = Get-NGBaseline -Name 'accounts'
    if ($null -eq $baseline) {
        Set-NGBaseline -Name 'accounts' -Value @($Accounts.users)
        Write-NGLog 'Recorded initial local account baseline.' -Agent $agentId
    }
    else {
        $diff = Compare-NGSnapshot -Baseline $baseline -Current @($Accounts.users) -Key 'key' -CompareProperties @('enabled', 'isAdmin')
        foreach ($n in @($diff.Added)) {
            $f.Add((New-NGFinding -Category 'Accounts' -Severity 'High' -Agent $agentId `
                        -Title "New local account created: $($n.name)" `
                        -Detail "Enabled: $($n.enabled). Administrator: $($n.isAdmin)." `
                        -Recommendation 'Account creation is a standard persistence step. If you did not create this, treat the host as compromised and investigate before deleting - the account is evidence.' `
                        -Evidence $n -FingerprintSeed "newaccount|$($n.key)"))
        }
        foreach ($c in @($diff.Changed)) {
            if (@($c.deltas | Where-Object { $_.property -eq 'isAdmin' -and "$($_.to)" -eq 'True' })) {
                $f.Add((New-NGFinding -Category 'Accounts' -Severity 'Critical' -Agent $agentId `
                            -Title "Account '$($c.current.name)' gained administrative rights" `
                            -Detail 'Privilege escalation via group membership.' `
                            -Recommendation 'If unexpected, remove the privilege immediately and investigate how it happened.' `
                            -Evidence $c -FingerprintSeed "promoted|$($c.key)"))
            }
            if (@($c.deltas | Where-Object { $_.property -eq 'enabled' -and "$($_.to)" -eq 'True' })) {
                $f.Add((New-NGFinding -Category 'Accounts' -Severity 'High' -Agent $agentId `
                            -Title "Disabled account '$($c.current.name)' was re-enabled" `
                            -Detail 'Re-enabling a dormant account is a low-noise way to regain access.' `
                            -Recommendation 'Confirm you did this.' -Evidence $c -FingerprintSeed "reenabled|$($c.key)"))
            }
        }
        Set-NGBaseline -Name 'accounts' -Value @($Accounts.users)
    }
    , @($f)
}

# ======================================================== CERTIFICATES =======

function Find-NGCertificateFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()]$Certificates)
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'certificates'

    $baseline = Get-NGBaseline -Name 'root-certs'
    if ($null -eq $baseline) {
        Set-NGBaseline -Name 'root-certs' -Value $Certificates
        Write-NGLog "Recorded initial trusted-root baseline ($(Get-NGCount $Certificates) certs)." -Agent $agentId
        return , @()
    }

    $diff = Compare-NGSnapshot -Baseline $baseline -Current @($Certificates) -Key 'key'
    foreach ($n in @($diff.Added)) {
        # Stores the OS itself maintains churn legitimately; operator-managed
        # stores do not.
        $sev = if ($n.systemManaged) { 'Medium' } else { 'High' }
        $f.Add((New-NGFinding -Category 'Certificates' -Severity $sev -Agent $agentId `
                    -Title "New trusted root certificate installed: $($n.subject)" `
                    -Detail ("Store: $($n.store)`nIssuer: $($n.issuer)`nFingerprint: $($n.thumbprint)`n" +
                             "Valid: $($n.notBefore) to $($n.notAfter)`n`n" +
                             'A certificate in this store can sign for ANY website without a warning. Common benign causes are corporate TLS inspection, a VPN client, an intercepting proxy, or antivirus HTTPS scanning. The malicious case is identical in appearance and enables silent interception of all TLS traffic.') `
                    -Recommendation 'Match the subject against software you installed. If you cannot account for it, remove it and then investigate what installed it.' `
                    -Evidence $n -FingerprintSeed "newroot|$($n.thumbprint)"))
    }
    Set-NGBaseline -Name 'root-certs' -Value $Certificates
    , @($f)
}

# =========================================================== INTEGRITY =======

function Find-NGHostsFileFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()]$Entries)
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'integrity'

    $securityDomains = 'microsoft|windowsupdate|defender|sophos|mcafee|symantec|kaspersky|malwarebytes|avast|bitdefender|eset|virustotal|clamav|trendmicro|ubuntu\.com|debian\.org|archlinux|fedoraproject'
    foreach ($e in @($Entries)) {
        if (-not $e) { continue }
        if ($e.entry -match $securityDomains) {
            $f.Add((New-NGFinding -Category 'Integrity' -Severity 'Critical' -Agent $agentId `
                        -Title 'Hosts file entry blocks a security or update domain' `
                        -Detail "Entry: $($e.entry)`n`nRedirecting antivirus or update domains in the hosts file is a well-established malware technique to prevent remediation and patching." `
                        -Recommendation 'Remove the entry, then run a full offline scan, because something put it there.' `
                        -Evidence $e -FingerprintSeed "hosts-security|$($e.entry)"))
        }
    }

    $baseline = Get-NGBaseline -Name 'hosts-file'
    if ($null -eq $baseline) {
        Set-NGBaseline -Name 'hosts-file' -Value $Entries
    }
    else {
        $diff = Compare-NGSnapshot -Baseline $baseline -Current @($Entries) -Key 'key'
        foreach ($n in @($diff.Added)) {
            $f.Add((New-NGFinding -Category 'Integrity' -Severity 'Medium' -Agent $agentId `
                        -Title 'Hosts file was modified' -Detail "New entry: $($n.entry)" `
                        -Recommendation 'Confirm you added this. The hosts file overrides DNS for every application on the machine.' `
                        -Evidence $n -FingerprintSeed "hosts-new|$($n.entry)"))
        }
        Set-NGBaseline -Name 'hosts-file' -Value $Entries
    }
    , @($f)
}

# ============================================================== EVENTS =======

function Find-NGEventFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Events,
        [int]$FailedLogonThreshold = 10
    )
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'events'

    if ((Get-NGCount $Events.logCleared) -gt 0) {
        $f.Add((New-NGFinding -Category 'Integrity' -Severity 'Critical' -Agent $agentId `
                    -Title 'Security audit log was cleared' `
                    -Detail 'Clearing the audit log destroys the record of what happened and is almost always deliberate anti-forensics. The OS does not do this on its own.' `
                    -Recommendation 'Treat as a probable compromise. Preserve remaining logs now, and if you forward logs off-box, review the copy there - that is the whole reason to forward them.' `
                    -Evidence @($Events.logCleared) -FingerprintSeed ('logcleared|' + (Get-Date -Format 'yyyy-MM-ddTHH'))))
    }

    $failed = @($Events.failedLogons)
    if ($failed.Count -ge $FailedLogonThreshold) {
        $bySource = $failed | Group-Object source | Sort-Object Count -Descending
        $top = $bySource | Select-Object -First 3 | ForEach-Object { "$($_.Name) x$($_.Count)" }
        $f.Add((New-NGFinding -Category 'Authentication' -Severity 'High' -Agent $agentId `
                    -Title "$($failed.Count) failed logons in $($Events.windowMinutes) minutes" `
                    -Detail ('Top sources: ' + ($top -join ', ') + '. Password spraying and brute force look exactly like this.') `
                    -Recommendation 'If the sources are external or unrecognised, block them at the firewall and confirm no service is exposed to the internet. Check that an account lockout policy exists.' `
                    -Evidence ($failed | Select-Object -First 25) `
                    -FingerprintSeed ('failedlogons|' + (($bySource | Select-Object -First 1).Name))))
    }

    foreach ($s in @($Events.newServices)) {
        $sev = 'Medium'
        if ($s.imagePath -match 'Temp|/tmp/|/dev/shm/|Public|powershell|cmd\.exe|rundll32|mshta|\.ps1|FromBase64|python\s+-c') { $sev = 'Critical' }
        $f.Add((New-NGFinding -Category 'Persistence' -Severity $sev -Agent $agentId `
                    -Title "New service installed: $($s.serviceName)" `
                    -Detail "Image path: $($s.imagePath)`nStart type: $($s.startType)`n`nService creation is how most remote-execution tooling runs code with full privilege." `
                    -Recommendation 'Match against software you installed. A service whose image path is a script interpreter or a temp directory is not a legitimate service.' `
                    -Evidence $s -FingerprintSeed "newservice|$($s.serviceName)"))
    }

    foreach ($d in @($Events.avDetections)) {
        $sev = switch ($d.kind) {
            'protection-disabled' { 'Critical' }
            'malware-detected' { 'High' }
            default { 'Medium' }
        }
        $snippet = "$($d.message)"
        if ($snippet.Length -gt 80) { $snippet = $snippet.Substring(0, 80) }
        $f.Add((New-NGFinding -Category 'Antivirus' -Severity $sev -Agent $agentId `
                    -Title "Antivirus event: $($d.kind)" -Detail $d.message `
                    -Recommendation 'For a detection, confirm it was quarantined and find out how it arrived. For a protection-disabled event, treat as compromise until proven otherwise.' `
                    -Evidence $d -FingerprintSeed "avevent|$($d.kind)|$snippet"))
    }

    foreach ($p in @($Events.suspiciousExecution)) {
        # Confidence comes from the collector indicator scoring, so a command that
        # only tripped weak patterns is not paged like an AMSI bypass.
        $sev = if ($p.confidence -eq 'high') { 'High' } else { 'Medium' }
        $occ = if ([int]$p.occurrences -gt 1) { " (seen $($p.occurrences)x)" } else { '' }
        $flat = ($p.command -replace '\s+', '')
        $seed = $flat.Substring(0, [Math]::Min(120, $flat.Length))
        $fence = '```'
        $f.Add((New-NGFinding -Category 'Execution' -Severity $sev -Agent $agentId `
                    -Title "Suspicious $($p.source) executed$occ" `
                    -Detail ("Matched indicators: $((@($p.indicators)) -join ', ')`n`n$fence`n$($p.command)`n$fence") `
                    -Recommendation 'Read the code. If you did not run it, find the parent process and treat it as active execution of attacker code.' `
                    -Evidence $p -FingerprintSeed "suspiciousexec|$seed"))
    }

    foreach ($t in @($Events.newScheduledTasks)) {
        $snippet = "$($t.message)"
        if ($snippet.Length -gt 80) { $snippet = $snippet.Substring(0, 80) }
        $f.Add((New-NGFinding -Category 'Persistence' -Severity 'Medium' -Agent $agentId `
                    -Title 'New scheduled task registered' -Detail $t.message `
                    -Recommendation 'Scheduled tasks are the most common persistence mechanism. Confirm this matches software you installed.' `
                    -Evidence $t -FingerprintSeed "newtask|$snippet"))
    }

    $interactive = @($Events.remoteLogons | Where-Object { $_.method -in 'RDP', 'SSH' })
    if ($interactive.Count -gt 0) {
        $sources = ($interactive | Group-Object source | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', '
        $f.Add((New-NGFinding -Category 'Authentication' -Severity 'Medium' -Agent $agentId `
                    -Title "Successful remote interactive logon(s) from $sources" `
                    -Detail 'Interactive remote sessions were established. Benign if it was you.' `
                    -Recommendation 'Confirm the source addresses are yours. An unrecognised successful remote logon is a confirmed intrusion, not a warning.' `
                    -Evidence $interactive -FingerprintSeed "remotelogon|$sources"))
    }

    , @($f)
}

# =========================================================== PERIMETER =======

function Find-NGPerimeterFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Perimeter)
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'perimeter'

    if ($Perimeter.upnpIgdFound) {
        $f.Add((New-NGFinding -Category 'Network' -Severity 'Medium' -Agent $agentId `
                    -Title 'Router has UPnP port mapping enabled' `
                    -Detail "An InternetGatewayDevice responded to SSDP discovery from $($Perimeter.upnpResponder). UPnP lets any program on the LAN - including malware and any compromised IoT device - open inbound ports through your router with no authentication and no record." `
                    -Recommendation 'Disable UPnP in the router admin interface and create by hand the handful of port forwards you actually need. Better still, replace port forwarding with WireGuard or Tailscale so nothing needs to be exposed.' `
                    -Evidence $Perimeter -FingerprintSeed 'upnp-enabled'))
    }

    if ($Perimeter.externalIp) {
        $prev = Get-NGState -Name 'external-ip' -Default $null
        if ($prev -and $prev.ip -and $prev.ip -ne $Perimeter.externalIp) {
            $f.Add((New-NGFinding -Category 'Network' -Severity 'Low' -Agent $agentId `
                        -Title "External IP changed: $($prev.ip) to $($Perimeter.externalIp)" `
                        -Detail 'Usually a normal DHCP lease change from your ISP. Worth noting because it also invalidates any IP allowlists you maintain elsewhere.' `
                        -Recommendation 'Update any firewall allowlists or dynamic DNS records that reference the old address.' `
                        -Evidence @{ from = $prev.ip; to = $Perimeter.externalIp } `
                        -FingerprintSeed "extip|$($Perimeter.externalIp)"))
        }
        Set-NGState -Name 'external-ip' -Value ([pscustomobject]@{
                ip = $Perimeter.externalIp; seen = (Get-Date).ToUniversalTime().ToString('o') })
    }

    if (@($Perimeter.gatewayAdminPorts) -contains 23) {
        $f.Add((New-NGFinding -Category 'Network' -Severity 'High' -Agent $agentId `
                    -Title 'Router is listening on Telnet (port 23)' `
                    -Detail 'Telnet on consumer router firmware is usually an undocumented backdoor or a debug interface left enabled, and it transmits credentials in cleartext.' `
                    -Recommendation 'Disable Telnet in the router settings. If there is no setting for it, the firmware is out of date or the device should be replaced.' `
                    -Evidence $Perimeter -FingerprintSeed 'gateway-telnet'))
    }

    , @($f)
}

Export-ModuleMember -Function *
