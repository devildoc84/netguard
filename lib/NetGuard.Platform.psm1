<#
    NetGuard.Platform - platform detection and provider loading.

    This is the seam. Everything above it (Core, Notify, AI, Detect, Harden,
    Scan, the agents) is platform-neutral and must stay that way. Everything
    below it lives in providers/<name>/ and may assume whatever its OS provides.

    The rule: no OS branch outside a provider. If shared code needs to know what
    OS it is on, that is a sign the contract is missing a function.

    ---------------------------------------------------------------- CONTRACT --

    A provider module MUST export these. The shared detectors consume the
    normalised shapes documented against each one, so a provider that returns
    the right shape gets every cross-platform rule for free.

      Get-NGProviderInfo        -> { name, displayName, osVersion, capabilities[] }
      Get-NGHostPosture         -> normalised posture (see below)
      Get-NGListeningPorts      -> [{ protocol, localAddress, port, processId,
                                      processName, processPath, scope,
                                      loopbackOnly, reachable, key }]
      Get-NGAutoruns            -> [{ type, location, name, command, key }]
      Get-NGLocalAccounts       -> { users:[{ name, enabled, isAdmin,
                                      passwordRequired, lastLogon, key }],
                                     adminMembers[], remoteUsers[] }
      Get-NGTrustedCertificates -> [{ store, subject, issuer, thumbprint,
                                      notBefore, notAfter, selfSigned, key }]
      Get-NGHostsFileEntries    -> [{ entry, key }]
      Get-NGSecurityEvents      -> { windowMinutes, since, failedLogons[],
                                     logCleared[], accountChanges[],
                                     newServices[], avDetections[],
                                     suspiciousExecution[], remoteLogons[] }
      Get-NGSignatureStatus     -> { status, signer, issuer, thumbprint, ... }
      Invoke-NGAntivirusScan    -> { ran, clean (TRI-STATE), detail }
      Get-NGHardeningChecks     -> [{ Id, Tier, Weight, Category, Title,
                                      Rationale, Risk, Test, Apply, Rollback }]
      Get-NGRemediationPreamble -> string prepended to generated Apply scripts
      Protect-NGSecretBytes     -> byte[] (encrypt)
      Unprotect-NGSecretBytes   -> byte[] (decrypt)
      Test-NGElevated           -> bool
      Find-NGPlatformPostureFindings -> findings from OS-specific rules

    OPTIONAL (the shared layer degrades gracefully if absent):

      Register-NGSchedule / Unregister-NGSchedule / Get-NGScheduleStatus
      Get-NGLanDevices          (a portable fallback lives in Detect)

    ------------------------------------------------- NORMALISED POSTURE -------

    Every provider fills these keys. Anything it cannot read is $null, NEVER a
    guess and never a default that reads as healthy. Detectors test `-eq $false`
    so that "unknown" stays silent instead of raising a false alarm.

      collectedAt, hostName, elevated, uptimeDays
      platform       { os, name, version, kernel, isServer }
      antivirus      { present, product, realtimeEnabled, signatureAgeDays,
                       lastScanAgeDays, tamperProtected, readable }
      firewall       [{ profile, enabled, defaultInbound, logging, readable }]
      diskEncryption [{ mount, status, method, readable }]
      secureBoot     $true / $false / $null
      patching       { daysSinceLastUpdate, autoUpdate, pendingSecurity, readable }
      logging        { commandAuditing, scriptLogging, adequateRetention }
      remoteAccess   { ssh { enabled, rootLogin, passwordAuth, port },
                       rdp { enabled, secure } }
      shares         [{ name, path, description }]
      raw            { ... provider-specific, surfaced in reports only ... }
#>

$script:NGProviderLoaded = $null
$script:NGProviderRoot = $null

function Get-NGPlatform {
    <#
        Returns 'Windows', 'Linux' or 'macOS'.

        $IsWindows / $IsLinux / $IsMacOS only exist in PowerShell 6+. On 5.1 they
        are simply undefined, which silently evaluates to $false - so checking
        them first on 5.1 would report the wrong OS rather than failing loudly.
        Version is therefore tested before the variables are trusted.
    #>
    if ($PSVersionTable.PSVersion.Major -lt 6) { return 'Windows' }
    if ($IsWindows) { return 'Windows' }
    if ($IsLinux) { return 'Linux' }
    if ($IsMacOS) { return 'macOS' }
    'Unknown'
}

function Get-NGProviderName {
    <# Directory name under providers/ for the current platform. #>
    switch (Get-NGPlatform) {
        'Windows' { 'windows' }
        'Linux' { 'linux' }
        'macOS' { 'macos' }
        default { $null }
    }
}

function Get-NGProviderPath {
    param([string]$Name)
    if (-not $Name) { $Name = Get-NGProviderName }
    if (-not $Name) { return $null }
    $libRoot = Split-Path -Parent $PSScriptRoot
    Join-Path $libRoot (Join-Path 'providers' $Name)
}

function Import-NGProvider {
    <#
        Loads the provider for this platform into the global scope.

        Imported globally on purpose: agents dot-source a bootstrap, then call
        provider functions from their own scope. A module-scoped import would
        resolve during bootstrap and then vanish.
    #>
    [CmdletBinding()]
    param([string]$Name, [switch]$Force)

    if (-not $Name) { $Name = Get-NGProviderName }
    if (-not $Name) {
        throw "Unsupported platform '$(Get-NGPlatform)'. NetGuard has providers for Windows and Linux."
    }
    if ($script:NGProviderLoaded -eq $Name -and -not $Force) { return $script:NGProviderLoaded }

    $dir = Get-NGProviderPath -Name $Name
    if (-not (Test-Path $dir)) {
        throw "No provider found at $dir. Expected a directory named '$Name' under providers/."
    }

    # Provider.psm1 first: Hardening.psm1 may use its helpers.
    foreach ($file in 'Provider.psm1', 'Hardening.psm1') {
        $p = Join-Path $dir $file
        if (Test-Path $p) { Import-Module $p -Force -DisableNameChecking -Global }
        elseif ($file -eq 'Provider.psm1') { throw "Provider '$Name' is missing Provider.psm1" }
    }

    $script:NGProviderLoaded = $Name
    $script:NGProviderRoot = $dir
    $Name
}

function Get-NGLoadedProvider { $script:NGProviderLoaded }

function Import-NGStack {
    <#
        THE loader. Imports every NetGuard module plus the platform provider, in
        dependency order, into the global scope.

        This exists because modules must not import each other. An
        Import-Module -Force from inside a module unloads and reloads the shared
        graph mid-import: module-scoped state is silently discarded (the loaded
        provider name came back empty) and command resolution starts failing in
        ways that only appear at runtime. Centralising load order here is the fix.

        Import this module, call Import-NGStack, and everything else is available.
    #>
    [CmdletBinding()]
    param([string]$ProviderName, [switch]$Force)

    $libDir = $PSScriptRoot

    # Core first - the providers call its null/type-safety helpers at runtime.
    Import-Module (Join-Path $libDir 'NetGuard.Core.psm1') -DisableNameChecking -Global -Force:$Force

    # Provider next - Detect and Harden call into it.
    $provider = Import-NGProvider -Name $ProviderName -Force:$Force

    foreach ($m in 'Notify', 'AI', 'Detect', 'Harden', 'Scan') {
        $path = Join-Path $libDir "NetGuard.$m.psm1"
        if (Test-Path $path) { Import-Module $path -DisableNameChecking -Global -Force:$Force }
    }

    [pscustomobject]@{
        platform = (Get-NGPlatform)
        provider = $provider
        modules  = @('Platform', 'Core', 'Notify', 'AI', 'Detect', 'Harden', 'Scan')
    }
}

function Test-NGProviderContract {
    <#
        Verifies the loaded provider implements the contract.

        Called by the self-test. A provider missing a required function would
        otherwise fail at 3am inside a scheduled run, where the symptom is an
        agent that reports nothing rather than an obvious error.
    #>
    [CmdletBinding()]
    param()
    $required = @(
        'Get-NGProviderInfo', 'Get-NGHostPosture', 'Get-NGListeningPorts', 'Get-NGAutoruns',
        'Get-NGLocalAccounts', 'Get-NGTrustedCertificates', 'Get-NGHostsFileEntries',
        'Get-NGSecurityEvents', 'Get-NGSignatureStatus', 'Invoke-NGAntivirusScan',
        'Get-NGHardeningChecks', 'Get-NGRemediationPreamble',
        'Protect-NGSecretBytes', 'Unprotect-NGSecretBytes', 'Test-NGElevated',
        'Find-NGPlatformPostureFindings'
    )
    $optional = @('Register-NGSchedule', 'Unregister-NGSchedule', 'Get-NGScheduleStatus', 'Get-NGLanDevices')

    $missing = @(); $present = @(); $missingOptional = @()
    foreach ($fn in $required) {
        if (Get-Command $fn -ErrorAction SilentlyContinue) { $present += $fn } else { $missing += $fn }
    }
    foreach ($fn in $optional) {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { $missingOptional += $fn }
    }
    [pscustomobject]@{
        provider        = $script:NGProviderLoaded
        platform        = (Get-NGPlatform)
        complete        = ($missing.Count -eq 0)
        implemented     = $present.Count
        requiredTotal   = $required.Count
        missing         = $missing
        missingOptional = $missingOptional
    }
}

function New-NGPosture {
    <#
        Returns a normalised posture skeleton with every field explicitly $null.

        Providers start from this instead of building a hashtable from scratch,
        so a field a provider forgets reads as "unknown" rather than being absent
        entirely - the difference between a detector staying quiet and a detector
        crashing on a missing property.
    #>
    [pscustomobject][ordered]@{
        collectedAt    = (Get-Date).ToUniversalTime().ToString('o')
        hostName       = [System.Net.Dns]::GetHostName()
        elevated       = $null
        uptimeDays     = $null
        platform       = [ordered]@{ os = (Get-NGPlatform); name = $null; version = $null; kernel = $null; isServer = $null }
        antivirus      = [ordered]@{ present = $null; product = $null; realtimeEnabled = $null
                                     signatureAgeDays = -1; lastScanAgeDays = -1
                                     tamperProtected = $null; readable = $false }
        firewall       = @()
        diskEncryption = @()
        secureBoot     = $null
        patching       = [ordered]@{ daysSinceLastUpdate = $null; autoUpdate = $null
                                     pendingSecurity = $null; readable = $false }
        logging        = [ordered]@{ commandAuditing = $null; scriptLogging = $null; adequateRetention = $null }
        remoteAccess   = [ordered]@{
            ssh = [ordered]@{ enabled = $null; rootLogin = $null; passwordAuth = $null; port = $null }
            rdp = [ordered]@{ enabled = $null; secure = $null }
        }
        shares         = @()
        raw            = [ordered]@{}
    }
}

Export-ModuleMember -Function *
