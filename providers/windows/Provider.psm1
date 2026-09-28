<#
    NetGuard Windows provider.

    Implements the contract in lib/NetGuard.Platform.psm1 for Windows 10/11 and
    Server. Targets PowerShell 5.1 so it runs on a stock install with nothing
    added.

    StrictMode is deliberately off: these run unattended against WMI and registry
    data whose shape changes between builds, and a missing property should
    degrade one check rather than kill the run.
#>

# Dependencies are loaded by Import-NGStack (lib/NetGuard.Platform.psm1),
# in order, exactly once. This module deliberately does NOT import its
# siblings: an Import-Module -Force from inside a module unloads and
# reloads the shared module graph mid-import, discarding module-scoped
# state and breaking command resolution in ways that only show up at
# runtime. Load order belongs to one place, not nine.
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue


function Get-NGProviderInfo {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    [pscustomobject]@{
        name         = 'windows'
        displayName  = 'Windows'
        osVersion    = if ($os) { "$($os.Caption) $($os.BuildNumber)" } else { 'Windows (unknown build)' }
        psVersion    = $PSVersionTable.PSVersion.ToString()
        capabilities = @('defender', 'firewall', 'bitlocker', 'eventlog', 'authenticode',
                         'dpapi', 'scheduledtasks', 'wmi', 'applocker')
    }
}

function Test-NGElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================================ SECRETS ========
<#
    DPAPI at LocalMachine scope. CurrentUser would be stronger, but the agents
    run as SYSTEM under Task Scheduler and could not decrypt a blob written by
    an interactive user. LocalMachine means the file ACL is the real control,
    which Protect-NGFilePath enforces.
#>

function Protect-NGSecretBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [byte[]]$Entropy)
    [System.Security.Cryptography.ProtectedData]::Protect($Bytes, $Entropy, 'LocalMachine')
}

function Unprotect-NGSecretBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [byte[]]$Entropy)
    [System.Security.Cryptography.ProtectedData]::Unprotect($Bytes, $Entropy, 'LocalMachine')
}

function Protect-NGFilePath {
    <#
        Restricts a file to SYSTEM + Administrators.

        Only acts when elevated. An unelevated admin holds a FILTERED token with
        no Administrators membership, so applying this from an unelevated shell
        locks the creator out of the file it just wrote.

        Operates on the DACL only: Set-Acl writes every section it holds,
        including the SACL, and writing a SACL needs SeSecurityPrivilege even
        when the caller owns the file.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    if (-not (Test-NGElevated)) { return $false }
    try {
        $fi = New-Object System.IO.FileInfo($Path)
        $sec = $fi.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        $sec.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($sec.GetAccessRules($true, $false, [System.Security.Principal.NTAccount]))) {
            try { $sec.RemoveAccessRuleSpecific($rule) } catch { }
        }
        foreach ($idn in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') {
            $ace = New-Object System.Security.AccessControl.FileSystemAccessRule($idn, 'FullControl', 'Allow')
            $sec.AddAccessRule($ace)
        }
        $fi.SetAccessControl($sec)
        $true
    }
    catch { $false }
}

function Reset-NGFilePathAcl {
    <# Recovery path for a file locked from the wrong context; the owner keeps WRITE_DAC. #>
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    try {
        $fi = New-Object System.IO.FileInfo($Path)
        $sec = $fi.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        foreach ($rule in @($sec.GetAccessRules($true, $false, [System.Security.Principal.NTAccount]))) {
            try { $sec.RemoveAccessRuleSpecific($rule) } catch { }
        }
        $sec.SetAccessRuleProtection($false, $true)
        $fi.SetAccessControl($sec)
        $true
    }
    catch { $false }
}

# ============================================================ POSTURE ========

function Get-NGHostPosture {
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue'
    $p = New-NGPosture
    $p.elevated = Test-NGElevated

    $os = Get-CimInstance Win32_OperatingSystem
    $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR -ErrorAction SilentlyContinue).UBR
    $p.platform.name = $os.Caption
    $p.platform.version = "$($os.BuildNumber).$ubr"
    $p.platform.kernel = $os.Version
    $p.platform.isServer = ($os.ProductType -ne 1)
    if ($os.LastBootUpTime) { $p.uptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1) }

    # ---------------------------------------------------------- antivirus ----
    # Retried explicitly: the Defender WMI provider intermittently returns
    # nothing under load, and treating that as "no Defender" would be both a
    # false alarm and a way to mask a genuinely disabled Defender.
    $mp = $null
    for ($i = 0; $i -lt 3; $i++) {
        try { $mp = Get-MpComputerStatus -ErrorAction Stop; if ($mp) { break } } catch { }
        Start-Sleep -Milliseconds 400
    }
    $p.antivirus.readable = ($null -ne $mp)
    if ($mp) {
        # Every field goes through the safe converters. A bare [int] cast here is
        # a terminating error that, under SilentlyContinue, abandons this entire
        # assignment - and a missing block reads as "nothing to report".
        $p.antivirus.present = $true
        $p.antivirus.product = 'Microsoft Defender'
        $p.antivirus.realtimeEnabled = (Get-NGSafeBool $mp.RealTimeProtectionEnabled)
        $p.antivirus.tamperProtected = (Get-NGSafeBool $mp.IsTamperProtected)
        $p.antivirus.signatureAgeDays = (Get-NGSafeInt $mp.AntivirusSignatureAge)
        $p.antivirus.lastScanAgeDays = (Get-NGSafeInt $mp.QuickScanAge)
    }

    $pref = Get-MpPreference
    $defenderRaw = $null
    if ($pref) {
        $asrIds = ConvertTo-NGArray $pref.AttackSurfaceReductionRules_Ids
        $asrActions = ConvertTo-NGArray $pref.AttackSurfaceReductionRules_Actions
        # Exclusions are only visible to an elevated caller; unelevated the cmdlet
        # returns a sentinel STRING that would otherwise be counted as a real path.
        $exclusionsReadable = -not (Test-NGAdminRestricted ($pref.ExclusionPath | Select-Object -First 1))
        $exPaths = if ($exclusionsReadable) { ConvertTo-NGArray $pref.ExclusionPath } else { @() }
        $defenderRaw = [ordered]@{
            asrRuleCount             = (Get-NGCount $asrIds)
            asrRuleIds               = $asrIds
            asrRuleActions           = $asrActions
            asrBlockModeCount        = (Get-NGCount @($asrActions | Where-Object { (Get-NGSafeInt $_) -eq 1 }))
            controlledFolderAccess   = (Get-NGSafeInt $pref.EnableControlledFolderAccess)
            networkProtection        = (Get-NGSafeInt $pref.EnableNetworkProtection)
            puaProtection            = (Get-NGSafeInt $pref.PUAProtection)
            cloudDeliveredProtection = (Get-NGSafeInt $pref.MAPSReporting)
            exclusionsReadable       = $exclusionsReadable
            exclusionPathCount       = (Get-NGCount $exPaths)
            exclusionPaths           = $exPaths
            exclusionProcesses       = if ($exclusionsReadable) { ConvertTo-NGArray $pref.ExclusionProcess } else { @() }
            scanScriptsEnabled       = (-not (Get-NGSafeBool $pref.DisableScriptScanning))
            tamperSource             = if ($mp) { [string]$mp.TamperProtectionSource } else { $null }
            engineVersion            = if ($mp) { [string]$mp.AMEngineVersion } else { $null }
        }
    }
    $p.raw.defender = $defenderRaw
    $p.raw.avProducts = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
        ForEach-Object { [ordered]@{ name = $_.displayName; state = $_.productState } })

    # ----------------------------------------------------------- firewall ----
    $p.firewall = @(Get-NetFirewallProfile | ForEach-Object {
            [ordered]@{
                profile        = [string]$_.Name
                enabled        = [bool]$_.Enabled
                defaultInbound = [string]$_.DefaultInboundAction
                logging        = ($_.LogBlocked -eq 'True')
                readable       = $true
                raw            = [ordered]@{
                    defaultOutbound = [string]$_.DefaultOutboundAction
                    logFileName     = [string]$_.LogFileName
                    logMaxSizeKb    = [int]$_.LogMaxSizeKilobytes
                }
            }
        })
    $p.raw.firewallInboundAllowRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
        Select-Object -First 400 | ForEach-Object {
            [ordered]@{ name = $_.DisplayName; profile = [string]$_.Profile; group = $_.DisplayGroup }
        })

    # ------------------------------------------------------ disk / platform --
    try { $p.secureBoot = [bool](Confirm-SecureBootUEFI) } catch { $p.secureBoot = $null }

    # Get-BitLockerVolume needs elevation, and without it the BitLocker module
    # emits nested Write-Error output that -ErrorAction cannot suppress. Skip the
    # call entirely rather than polluting the log, and record it as unknown so
    # the detector does not claim the disk is unencrypted.
    if ($p.elevated) {
        try {
            $bl = Get-BitLockerVolume -ErrorAction Stop 2>$null
            $p.diskEncryption = @($bl | ForEach-Object {
                    [ordered]@{ mount = [string]$_.MountPoint; status = [string]$_.ProtectionStatus
                                method = [string]$_.EncryptionMethod; readable = $true }
                })
        }
        catch { }
    }

    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
    if ($dg) {
        $p.raw.deviceGuard = [ordered]@{
            vbsStatus              = (Get-NGSafeInt $dg.VirtualizationBasedSecurityStatus)
            servicesRunning        = @($dg.SecurityServicesRunning)
            hvciRunning            = (@($dg.SecurityServicesRunning) -contains 2)
            credentialGuardRunning = (@($dg.SecurityServicesRunning) -contains 1)
        }
    }
    $tpm = Get-Tpm
    if ($tpm) { $p.raw.tpm = [ordered]@{ present = [bool]$tpm.TpmPresent; ready = [bool]$tpm.TpmReady } }

    # ------------------------------------------------------------ policies ---
    function _reg($path, $name) {
        $v = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        if ($v) { return $v.$name }
        $null
    }
    $pol = [ordered]@{
        uacEnabled                = _reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
        uacConsentPromptAdmin     = _reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
        lsaRunAsPPL               = _reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
        wdigestUseLogonCredential = _reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
        psScriptBlockLogging      = _reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
        cmdProcessAuditing        = _reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
        rdpDenied                 = _reg 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        rdpNla                    = _reg 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
        llmnrEnableMulticast      = _reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
        autorunDisabled           = _reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
        installElevatedAlways     = _reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    }
    $p.raw.policies = $pol

    $p.logging.commandAuditing = ((Get-NGSafeInt $pol.cmdProcessAuditing) -eq 1)
    $p.logging.scriptLogging = ((Get-NGSafeInt $pol.psScriptBlockLogging) -eq 1)
    $secLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    if ($secLog) { $p.logging.adequateRetention = ($secLog.MaximumSizeInBytes -ge 268435456) }

    $p.remoteAccess.rdp.enabled = ((Get-NGSafeInt $pol.rdpDenied -Default 1) -eq 0)
    $p.remoteAccess.rdp.secure = ((Get-NGSafeInt $pol.rdpNla) -eq 1)

    # ---------------------------------------------------------------- SMB ----
    $smb = Get-SmbServerConfiguration
    if ($smb) {
        $p.raw.smb = [ordered]@{
            smb1Enabled    = [bool]$smb.EnableSMB1Protocol
            requireSigning = (Get-NGSafeBool $smb.RequireSecuritySignature)
            encryptData    = (Get-NGSafeBool $smb.EncryptData)
        }
    }
    $p.shares = @(Get-SmbShare | ForEach-Object {
            [ordered]@{ name = $_.Name; path = $_.Path; description = $_.Description }
        })

    # ----------------------------------------------------------- patching ----
    try {
        $hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hotfix -and $hotfix.InstalledOn) {
            $p.patching.daysSinceLastUpdate = [math]::Round(((Get-Date) - $hotfix.InstalledOn).TotalDays, 0)
            $p.patching.readable = $true
            $p.raw.lastHotfix = [string]$hotfix.HotFixID
        }
    }
    catch { }
    $wu = Get-Service wuauserv -ErrorAction SilentlyContinue
    if ($wu) { $p.patching.autoUpdate = ($wu.StartType -ne 'Disabled'); $p.raw.wuStartType = [string]$wu.StartType }

    $p
}

# ============================================================== NETWORK ======

function Get-NGAddressScopeMap {
    <#
        Maps each local IP to how much exposure it represents. On a host running
        VMware, Hyper-V or a mesh VPN most "exposed" addresses are host-only
        switches nobody can reach; scoring them like the real LAN address turns
        one issue into six duplicate alerts.
    #>
    $virtualAlias = 'VMware|VMnet|vEthernet|Hyper-V|Loopback|Bluetooth|Radmin|TAP|VirtualBox|Tailscale|WireGuard|ZeroTier'
    $map = @{}
    foreach ($cfg in (Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {
        $isVirtual = ($cfg.InterfaceAlias -match $virtualAlias)
        foreach ($fam in 'IPv4Address', 'IPv6Address') {
            foreach ($addr in @($cfg.$fam)) {
                if (-not $addr) { continue }
                $map[[string]$addr.IPAddress] = [pscustomobject]@{
                    interface = $cfg.InterfaceAlias
                    scope     = if ($isVirtual) { 'virtual' } else { 'lan' }
                }
            }
        }
    }
    $map
}

function Get-NGLocalSubnet {
    <#
        Returns the CIDR of the primary physical LAN, skipping the virtual
        adapters that VMware/Hyper-V/mesh VPNs create. Discovery uses this so it
        sweeps the real network rather than an empty hypervisor switch.
    #>
    $excludePattern = 'VMware|VMnet|vEthernet|Hyper-V|Loopback|Bluetooth|Radmin|TAP|VirtualBox|Tailscale|WireGuard|ZeroTier'
    $cands = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object {
        $_.IPv4Address -and $_.IPv4DefaultGateway -and $_.InterfaceAlias -notmatch $excludePattern
    }
    foreach ($c in $cands) {
        $ip = $c.IPv4Address.IPAddress
        if ($ip -like '169.254.*') { continue }
        $prefix = $c.IPv4Address.PrefixLength
        $octets = $ip.Split('.')
        # The subnet is returned whatever its size. Only the host-by-host SWEEP
        # needs a narrow prefix; rejecting a /20 outright also disabled the
        # gateway, UPnP and external-IP checks, which do not care how big the
        # network is.
        return [pscustomobject]@{
            Interface = $c.InterfaceAlias
            IPAddress = $ip
            Prefix    = $prefix
            Gateway   = $c.IPv4DefaultGateway.NextHop
            Base      = ('{0}.{1}.{2}' -f $octets[0], $octets[1], $octets[2])
            Cidr      = ('{0}.{1}.{2}.0/{3}' -f $octets[0], $octets[1], $octets[2], $prefix)
            Sweepable = ($prefix -ge 22)
        }
    }
    $null
}

function Get-NGListeningPorts {
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue'
    $procCache = @{}
    Get-Process | ForEach-Object { $procCache[$_.Id] = $_ }
    $scopeMap = Get-NGAddressScopeMap

    function _classify($addr) {
        if ($addr -in @('127.0.0.1', '::1')) { return 'loopback' }
        # A wildcard bind listens on every current AND future interface, so it is
        # the broadest exposure regardless of what exists right now.
        if ($addr -in @('0.0.0.0', '::')) { return 'any' }
        if ($addr -like 'fe80:*' -or $addr -like '169.254.*') { return 'linklocal' }
        if ($scopeMap.ContainsKey($addr)) { return $scopeMap[$addr].scope }
        'other'
    }

    $emit = {
        param($proto, $obj)
        $pr = $procCache[[int]$obj.OwningProcess]
        $addr = [string]$obj.LocalAddress
        $scope = _classify $addr
        [pscustomobject][ordered]@{
            protocol     = $proto
            localAddress = $addr
            port         = [int]$obj.LocalPort
            processId    = [int]$obj.OwningProcess
            processName  = if ($pr) { $pr.ProcessName } else { 'unknown' }
            processPath  = if ($pr) { $pr.Path } else { $null }
            scope        = $scope
            loopbackOnly = ($scope -eq 'loopback')
            reachable    = ($scope -in @('any', 'lan'))
            key          = "$proto/$($obj.LocalPort)/$addr"
        }
    }

    $tcp = Get-NetTCPConnection -State Listen | ForEach-Object { & $emit 'TCP' $_ }
    $udp = Get-NetUDPEndpoint | ForEach-Object { & $emit 'UDP' $_ }
    , @($tcp + $udp | Sort-Object protocol, port)
}

function Get-NGLanDevices {
    [CmdletBinding()]
    param([switch]$SkipSweep, [int]$SweepTimeoutMs = 400)
    $ErrorActionPreference = 'SilentlyContinue'

    $subnet = Get-NGLocalSubnet
    if (-not $subnet) { return @() }

    if (-not $subnet.Sweepable) {
        Write-NGLog "LAN $($subnet.Cidr) is wider than /22; skipping the host sweep and using the neighbour table only." -Level DEBUG -Agent discovery -Quiet
        $SkipSweep = $true
    }
    if (-not $SkipSweep) {
        # Async pings so a /24 finishes in about a second instead of two minutes.
        $pings = @()
        foreach ($i in 1..254) {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $pings += [pscustomobject]@{ Ping = $ping; Task = $ping.SendPingAsync("$($subnet.Base).$i", $SweepTimeoutMs) }
        }
        try { [Threading.Tasks.Task]::WaitAll(@($pings.Task), ($SweepTimeoutMs + 1500)) } catch { }
        foreach ($pg in $pings) { try { $pg.Ping.Dispose() } catch { } }
    }

    $neighbors = Get-NetNeighbor -AddressFamily IPv4 | Where-Object {
        $_.State -in 'Reachable', 'Stale', 'Permanent' -and
        $_.IPAddress -like "$($subnet.Base).*" -and
        $_.LinkLayerAddress -and $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' -and
        $_.IPAddress -notlike '*.255'
    }
    $out = foreach ($n in $neighbors) {
        $hostname = $null
        try { $hostname = [Net.Dns]::GetHostEntry($n.IPAddress).HostName } catch { }
        $mac = ($n.LinkLayerAddress -replace '-', ':').ToUpper()
        [pscustomobject][ordered]@{
            mac = $mac; ipAddress = [string]$n.IPAddress; hostName = $hostname
            vendor = (Get-NGVendorFromMac $mac); state = [string]$n.State
            isGateway = ($n.IPAddress -eq $subnet.Gateway)
            firstSeen = (Get-Date).ToUniversalTime().ToString('o')
            lastSeen = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
    , @($out)
}

function Get-NGSignatureStatus {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        [pscustomobject]@{
            status      = [string]$s.Status
            signer      = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null }
            issuer      = if ($s.SignerCertificate) { $s.SignerCertificate.Issuer } else { $null }
            thumbprint  = if ($s.SignerCertificate) { $s.SignerCertificate.Thumbprint } else { $null }
            notAfter    = if ($s.SignerCertificate) { $s.SignerCertificate.NotAfter } else { $null }
            timeStamped = ($null -ne $s.TimeStamperCertificate)
            supported   = $true
        }
    }
    catch {
        [pscustomobject]@{ status = 'Error'; signer = $null; issuer = $null; thumbprint = $null
                           notAfter = $null; timeStamped = $false; supported = $true }
    }
}

# ========================================================== PERSISTENCE ======

function Get-NGAutoruns {
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue'
    $items = New-Object System.Collections.Generic.List[psobject]

    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        # NOTE: Explorer\Shell Folders is deliberately NOT here. It holds folder
        # locations, not autostart commands, so its values (CommonPictures =
        # C:\Users\Public\Pictures) match "executes from a user-writable path"
        # and generate guaranteed false positives on every host.
    )
    foreach ($k in $runKeys) {
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($pr in $props.PSObject.Properties) {
            if ($pr.Name -like 'PS*') { continue }
            if ($k -like '*Winlogon*' -and $pr.Name -notin 'Userinit', 'Shell', 'Taskman', 'AppSetup') { continue }
            $items.Add([pscustomobject][ordered]@{
                    type = 'RegistryRun'; location = $k; name = $pr.Name
                    command = [string]$pr.Value; key = "RegistryRun|$k|$($pr.Name)"
                })
        }
    }

    foreach ($dir in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")) {
        Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | ForEach-Object {
            $items.Add([pscustomobject][ordered]@{
                    type = 'StartupFolder'; location = $dir; name = $_.Name
                    command = $_.FullName; key = "StartupFolder|$($_.FullName)"
                })
        }
    }

    Get-CimInstance Win32_Service | Where-Object { $_.StartMode -in 'Auto', 'Manual' } | ForEach-Object {
        $items.Add([pscustomobject][ordered]@{
                type = 'Service'; location = $_.Name; name = $_.DisplayName
                command = [string]$_.PathName; account = [string]$_.StartName
                key = "Service|$($_.Name)"
            })
    }

    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
        $actions = @($_.Actions | ForEach-Object {
                if ($_.Execute) { "$($_.Execute) $($_.Arguments)".Trim() } else { $_.ClassId }
            }) -join ' ;; '
        $items.Add([pscustomobject][ordered]@{
                type = 'ScheduledTask'; location = $_.TaskPath; name = $_.TaskName
                command = $actions; account = [string]$_.Principal.UserId
                key = "ScheduledTask|$($_.TaskPath)$($_.TaskName)"
            })
    }

    # WMI event subscriptions - a classic fileless persistence spot most people
    # never look at.
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        ForEach-Object {
            $items.Add([pscustomobject][ordered]@{
                    type = 'WmiSubscription'; location = 'root\subscription'
                    name = [string]$_.Filter; command = [string]$_.Consumer
                    key = "WmiSubscription|$($_.Filter)|$($_.Consumer)"
                })
        }
    , @($items)
}

function Get-NGLocalAccounts {
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue'
    $admins = @()
    try { $admins = @(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { [string]$_.Name }) } catch { }
    $users = Get-LocalUser | ForEach-Object {
        [pscustomobject][ordered]@{
            name             = $_.Name
            enabled          = [bool]$_.Enabled
            isAdmin          = ($admins -contains "$env:COMPUTERNAME\$($_.Name)" -or $admins -contains $_.Name)
            passwordRequired = [bool]$_.PasswordRequired
            passwordLastSet  = $_.PasswordLastSet
            lastLogon        = $_.LastLogon
            principalSource  = [string]$_.PrincipalSource
            isBuiltinAdmin   = ([string]$_.SID -match '-500$')
            key              = [string]$_.SID
        }
    }
    [pscustomobject]@{
        users        = @($users)
        adminMembers = $admins
        remoteUsers  = @(try { Get-LocalGroupMember -Group 'Remote Desktop Users' | ForEach-Object { [string]$_.Name } } catch { })
    }
}

function Get-NGTrustedCertificates {
    <#
        Rogue root CA detection. A trusted root the user did not install is one
        of the highest-signal, lowest-noise indicators of TLS interception, and
        almost nobody monitors it.
    #>
    [CmdletBinding()]
    param()
    $ErrorActionPreference = 'SilentlyContinue'
    $out = foreach ($store in 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\AuthRoot', 'Cert:\CurrentUser\Root') {
        Get-ChildItem -Path $store -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject][ordered]@{
                store = $store; subject = $_.Subject; issuer = $_.Issuer
                thumbprint = $_.Thumbprint; notBefore = $_.NotBefore; notAfter = $_.NotAfter
                selfSigned = ($_.Subject -eq $_.Issuer)
                systemManaged = ($store -like '*AuthRoot*')
                key = "$store|$($_.Thumbprint)"
            }
        }
    }
    , @($out)
}

function Get-NGHostsFileEntries {
    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (-not (Test-Path $hosts)) { return @() }
    $out = Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#')) { [pscustomobject]@{ entry = $line; key = $line } }
    }
    , @($out)
}

# =============================================================== EVENTS ======

function Get-NGSecurityEvents {
    [CmdletBinding()]
    param([int]$SinceMinutes = 20)
    $ErrorActionPreference = 'SilentlyContinue'
    $start = (Get-Date).AddMinutes(-$SinceMinutes)
    $result = [ordered]@{
        windowMinutes = $SinceMinutes; since = $start.ToString('o')
        failedLogons = @(); logCleared = @(); accountChanges = @(); newScheduledTasks = @()
        newServices = @(); avDetections = @(); suspiciousExecution = @(); remoteLogons = @()
    }

    function _q($logName, $ids) {
        try { Get-WinEvent -FilterHashtable @{ LogName = $logName; ID = $ids; StartTime = $start } -ErrorAction Stop }
        catch { @() }
    }

    $sec = _q 'Security' @(1102, 4625, 4720, 4726, 4732, 4728, 4698, 4624)
    $result.failedLogons = @($sec | Where-Object { $_.Id -eq 4625 } | ForEach-Object {
            $x = [xml]$_.ToXml()
            [pscustomobject]@{
                time = $_.TimeCreated
                target = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                source = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                method = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            }
        })
    $result.logCleared = @($sec | Where-Object { $_.Id -eq 1102 } | ForEach-Object {
            [pscustomobject]@{ time = $_.TimeCreated; message = $_.Message } })
    $result.accountChanges = @($sec | Where-Object { $_.Id -in 4720, 4726, 4732, 4728 } | ForEach-Object {
            [pscustomobject]@{ time = $_.TimeCreated; id = $_.Id; message = ($_.Message -split "`n")[0] } })
    $result.newScheduledTasks = @($sec | Where-Object { $_.Id -eq 4698 } | ForEach-Object {
            [pscustomobject]@{ time = $_.TimeCreated; message = ($_.Message -split "`n")[0] } })

    $result.newServices = @((_q 'System' @(7045)) | ForEach-Object {
            $x = [xml]$_.ToXml()
            [pscustomobject]@{
                time = $_.TimeCreated
                serviceName = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
                imagePath = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'ImagePath' }).'#text'
                startType = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'StartType' }).'#text'
            }
        })

    $result.avDetections = @((_q 'Microsoft-Windows-Windows Defender/Operational' @(1006, 1015, 1116, 1117, 5001, 5010, 5012)) |
        ForEach-Object {
            # 5001/5010/5012 mean protection was switched off - treat as the most severe.
            $sev = if ($_.Id -in 5001, 5010, 5012) { 'protection-disabled' }
                   elseif ($_.Id -eq 1116) { 'malware-detected' } else { 'action-taken' }
            [pscustomobject]@{ time = $_.TimeCreated; id = $_.Id; kind = $sev
                               message = (($_.Message -split "`n")[0..3] -join ' ') }
        })

    <#
        PowerShell script block triage.

        A single weak indicator is not evidence. Invoke-Expression and
        Net.WebClient appear constantly in legitimate tooling - including this
        module's own pattern list - which made the first version detect itself
        18 times per run. Fire on ONE high-confidence indicator or TWO weak ones,
        never on NetGuard's own code, and collapse identical blocks.
    #>
    $highConfidence = @(
        'AmsiUtils|amsiInitFailed|AmsiScanBuffer'
        '-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,}'
        'Add-MpPreference\s+-ExclusionPath'
        'Set-MpPreference\s+.*-Disable\w*\s+\$true'
        'DownloadString\([^)]*\)\s*\)?\s*\|?\s*(iex|Invoke-Expression)'
        'WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection'
        'vssadmin.{0,30}delete\s+shadows'
    )
    $weak = @('FromBase64String', 'Invoke-Expression|\biex\b', 'DownloadString|DownloadFile',
        'Net\.WebClient', 'Reflection\.Assembly', 'VirtualAlloc',
        'certutil.{0,30}-urlcache', 'bitsadmin.{0,30}/transfer', '-bypass\s+-nop|-nop\s+-w\s+hidden')
    $selfPattern = 'NetGuard|\\netguard\\|Invoke-NGStage|Find-NG[A-Za-z]+Findings|__claudeCodeScript'

    $blocks = @{}
    foreach ($ev in (_q 'Microsoft-Windows-PowerShell/Operational' @(4104))) {
        $msg = [string]$ev.Message
        if ([string]::IsNullOrWhiteSpace($msg)) { continue }
        if ($msg -match $selfPattern) { continue }
        $hits = @(); $isHigh = $false
        foreach ($rx in $highConfidence) { if ($msg -match $rx) { $isHigh = $true; $hits += "high:$rx" } }
        foreach ($rx in $weak) { if ($msg -match $rx) { $hits += "weak:$rx" } }
        if (-not $isHigh -and (Get-NGCount @($hits | Where-Object { $_ -like 'weak:*' })) -lt 2) { continue }

        $t = $msg
        if ($t.Length -gt 1500) { $t = $t.Substring(0, 1500) + '...[truncated]' }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $k = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($t))) -replace '-', '').Substring(0, 16)
        if ($blocks.ContainsKey($k)) { $blocks[$k].occurrences++; continue }
        $blocks[$k] = [pscustomobject]@{
            time = $ev.TimeCreated; source = 'PowerShell script block'; command = $t
            confidence = if ($isHigh) { 'high' } else { 'medium' }
            indicators = $hits; occurrences = 1
        }
    }
    $result.suspiciousExecution = @($blocks.Values)

    $result.remoteLogons = @($sec | Where-Object { $_.Id -eq 4624 } | ForEach-Object {
            $x = [xml]$_.ToXml()
            $lt = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            if ($lt -in '3', '10') {
                [pscustomobject]@{
                    time = $_.TimeCreated
                    method = if ($lt -eq '10') { 'RDP' } else { 'Network' }
                    user = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    source = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                }
            }
        } | Where-Object { $_ -and $_.user -notlike '*$' -and $_.source -notin '-', '127.0.0.1', '::1' })

    [pscustomobject]$result
}

# ========================================================== AV SCANNING ======

function Invoke-NGAntivirusScan {
    <#
        On-demand Defender scan of one file.

        The verdict comes from the OUTPUT TEXT, not the exit code. A non-zero
        exit can mean a bad argument, a stopped service or an access denial, and
        treating any of those as a detection quarantines every clean file - which
        is exactly what an earlier version did. Anything not positively
        classified stays $null (unknown) and is excluded from scoring.
    #>
    param([Parameter(Mandatory = $true)][string]$Path, [int]$TimeoutSeconds = 120)

    $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (-not (Test-Path $mp)) {
        $plat = Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform' -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($plat) { $mp = Join-Path $plat.FullName 'MpCmdRun.exe' }
    }
    if (-not (Test-Path $mp)) {
        return [pscustomobject]@{ ran = $false; clean = $null; engine = 'defender'; detail = 'MpCmdRun.exe not found' }
    }

    $outFile = Join-Path $env:TEMP ("ng-mp-{0}.txt" -f [guid]::NewGuid().ToString('N'))
    try {
        # -ArgumentList must be ONE raw command-line string. Passing an array makes
        # Start-Process re-quote each element, corrupting a quoted path.
        $argLine = "-Scan -ScanType 3 -File `"$Path`" -DisableRemediation"
        $proc = Start-Process -FilePath $mp -ArgumentList $argLine -NoNewWindow -PassThru `
            -RedirectStandardOutput $outFile -ErrorAction Stop
        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            try { $proc.Kill() } catch { }
            return [pscustomobject]@{ ran = $false; clean = $null; engine = 'defender'; detail = 'scan timed out' }
        }
        $out = ''
        if (Test-Path $outFile) { $out = (Get-Content -LiteralPath $outFile -Raw) }
        $flat = ($out -replace '\s+', ' ').Trim()

        $clean = $null
        if ($flat -match 'found no threats') { $clean = $true }
        elseif ($flat -match 'found\s+\d+\s+threat|Threat\s+information|was detected|Category:\s') { $clean = $false }
        elseif ($proc.ExitCode -eq 2) { $clean = $false }
        elseif ($proc.ExitCode -eq 0 -and $flat -match 'Scan finished') { $clean = $true }

        [pscustomobject]@{ ran = ($null -ne $clean); clean = $clean; engine = 'defender'
                           exitCode = $proc.ExitCode; detail = $flat }
    }
    catch { [pscustomobject]@{ ran = $false; clean = $null; engine = 'defender'; detail = $_.Exception.Message } }
    finally { if (Test-Path $outFile) { Remove-Item $outFile -Force -ErrorAction SilentlyContinue } }
}

# ============================================================ SCHEDULING =====

function Register-NGSchedule {
    <# Registers the NetGuard scheduled tasks. See install/Register-Tasks.ps1. #>
    param([Parameter(Mandatory = $true)]$Jobs, [string]$NGRoot, [string]$UserPrincipal)

    $PS = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $registered = @()
    foreach ($j in $Jobs) {
        $scriptPath = Join-Path $NGRoot $j.Script
        if (-not (Test-Path $scriptPath)) { continue }
        $argLine = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`""
        if ($j.Arguments) { $argLine += " $($j.Arguments)" }
        $action = New-ScheduledTaskAction -Execute $PS -Argument $argLine -WorkingDirectory $NGRoot

        $trigger = switch ($j.Schedule) {
            'interval' {
                New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes($j.OffsetMinutes) `
                    -RepetitionInterval (New-TimeSpan -Minutes $j.IntervalMinutes) `
                    -RepetitionDuration ([TimeSpan]::MaxValue)
            }
            'daily' { New-ScheduledTaskTrigger -Daily -At $j.At }
            'weekly' { New-ScheduledTaskTrigger -Weekly -DaysOfWeek $j.DayOfWeek -At $j.At }
            'logon' { New-ScheduledTaskTrigger -AtLogOn -User $UserPrincipal }
        }

        if ($j.RunAs -eq 'SYSTEM') {
            $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        }
        else {
            $principal = New-ScheduledTaskPrincipal -UserId $UserPrincipal -LogonType Interactive -RunLevel Limited
        }

        $sArgs = @{
            AllowStartIfOnBatteries = $true; DontStopIfGoingOnBatteries = $true
            StartWhenAvailable = $true; MultipleInstances = 'IgnoreNew'
            RestartCount = 3; RestartInterval = (New-TimeSpan -Minutes 5); DontStopOnIdleEnd = $true
        }
        # A watcher is meant to run forever; the default 3-day kill would stop it.
        $sArgs['ExecutionTimeLimit'] = if ($j.LongRunning) { (New-TimeSpan -Seconds 0) } else { (New-TimeSpan -Hours 1) }
        $settings = New-ScheduledTaskSettingsSet @sArgs

        Register-ScheduledTask -TaskName $j.Name -TaskPath '\NetGuard\' -Action $action `
            -Trigger $trigger -Principal $principal -Settings $settings `
            -Description $j.Description -Force | Out-Null
        $registered += $j.Name
    }
    $registered
}

function Unregister-NGSchedule {
    $tasks = Get-ScheduledTask -TaskPath '\NetGuard\' -ErrorAction SilentlyContinue
    $removed = @()
    foreach ($t in $tasks) {
        Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false
        $removed += $t.TaskName
    }
    $removed
}

function Get-NGScheduleStatus {
    Get-ScheduledTask -TaskPath '\NetGuard\' -ErrorAction SilentlyContinue | ForEach-Object {
        $info = $_ | Get-ScheduledTaskInfo
        [pscustomobject]@{
            name = $_.TaskName; state = [string]$_.State
            lastRun = $info.LastRunTime; nextRun = $info.NextRunTime
            lastResult = $info.LastTaskResult
        }
    }
}

Export-ModuleMember -Function *
