<#
.SYNOPSIS
    Deploy NetGuard to other Windows machines on the LAN over WinRM.

.DESCRIPTION
    Copies the NetGuard tree to each target, installs the scheduled tasks there,
    and points the target at this machine as the collection point so findings land
    in one place.

    DESIGN NOTE - why the hub is a file share and not a listening service:
    a central collector is itself an attack surface, and a service listening on
    every monitored host is exactly the kind of thing this tool is meant to warn
    you about. Instead each agent writes its findings to a share on the hub. No
    inbound port on the spokes, nothing new to authenticate, and if the hub is
    offline the spoke keeps working and backfills later.

    PREREQUISITES on each target:
      * WinRM enabled              (Enable-PSRemoting -Force)
      * you have admin credentials there
      * for non-domain machines, the target must be in this host's TrustedHosts

    This script does NOT enable WinRM for you. Turning on remote management
    across a network is your decision to make deliberately, not a side effect of
    running a deployment script.

.PARAMETER ComputerName
    Targets. Defaults to the hosts listed in config\netguard.config.json.

.PARAMETER Credential
    Admin credentials for the targets. You will be prompted if omitted.

.PARAMETER HubShare
    UNC path this machine exposes for collected findings, e.g. \\HUB-PC\NetGuardHub.

.PARAMETER TestOnly
    Check connectivity and prerequisites without changing anything.

.EXAMPLE
    .\Deploy-Agent.ps1 -ComputerName DESKTOP-2,LAPTOP-3 -TestOnly

.EXAMPLE
    .\Deploy-Agent.ps1 -ComputerName LAPTOP-3 -HubShare \\HUB-PC\NetGuardHub
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string[]]$ComputerName,
    [pscredential]$Credential,
    [string]$RemoteRoot = 'C:\ProgramData\NetGuard',
    [string]$HubShare,
    [switch]$TestOnly,
    [switch]$NoTasks
)

$ErrorActionPreference = 'Stop'
$NGRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $NGRoot 'lib\NetGuard.Core.psm1') -Force -DisableNameChecking

$cfg = $null
try { $cfg = Get-NGConfig } catch { }
if (-not $ComputerName) {
    if ($cfg -and $cfg.remote.hosts) { $ComputerName = @($cfg.remote.hosts) }
}
if ((Get-NGCount $ComputerName) -eq 0) {
    throw "No targets. Pass -ComputerName, or add them to config\netguard.config.json under remote.hosts."
}

Write-Host ''
Write-Host '  NetGuard remote deployment' -ForegroundColor Cyan
Write-Host "  Source : $NGRoot" -ForegroundColor DarkGray
Write-Host "  Targets: $($ComputerName -join ', ')" -ForegroundColor DarkGray
Write-Host "  Remote : $RemoteRoot" -ForegroundColor DarkGray
Write-Host ''

if (-not $Credential -and -not $TestOnly) {
    Write-Host '  Enter administrator credentials valid on the target machines.' -ForegroundColor Yellow
    $Credential = Get-Credential -Message 'NetGuard remote deployment'
}

# ------------------------------------------------------------ preflight ------

$ready = @()
foreach ($c in $ComputerName) {
    $state = [ordered]@{ computer = $c; reachable = $false; winrm = $false; note = '' }
    try {
        $state.reachable = Test-Connection -ComputerName $c -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $state.reachable) { $state.note = 'does not respond to ping (may still be up with ICMP blocked)' }

        $params = @{ ComputerName = $c; ErrorAction = 'Stop' }
        if ($Credential) { $params.Credential = $Credential }
        $info = Invoke-Command @params -ScriptBlock {
            [pscustomobject]@{
                os        = (Get-CimInstance Win32_OperatingSystem).Caption
                psVersion = $PSVersionTable.PSVersion.ToString()
                admin     = (New-Object Security.Principal.WindowsPrincipal(
                        [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole('Administrators')
            }
        }
        $state.winrm = $true
        $state.note = "$($info.os), PS $($info.psVersion), admin=$($info.admin)"
        if (-not $info.admin) { $state.note += ' -- NOT ADMIN, deployment will fail' }
    }
    catch {
        $state.note = "WinRM failed: $($_.Exception.Message -replace '\s+', ' ')"
    }
    $ready += [pscustomobject]$state
    $color = if ($state.winrm) { 'Green' } else { 'Red' }
    Write-Host ("  {0,-18} winrm={1,-6} {2}" -f $c, $state.winrm, $state.note) -ForegroundColor $color
}

Write-Host ''
if ($TestOnly) {
    Write-Host '  Preflight only; nothing was changed.' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  If WinRM failed, on the TARGET run (elevated):' -ForegroundColor White
    Write-Host '    Enable-PSRemoting -Force' -ForegroundColor Yellow
    Write-Host '  and for a workgroup (non-domain) target, on THIS machine run:' -ForegroundColor White
    Write-Host "    Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'NAME1,NAME2' -Concatenate" -ForegroundColor Yellow
    Write-Host ''
    return $ready
}

$deployable = @($ready | Where-Object { $_.winrm })
if ((Get-NGCount $deployable) -eq 0) { throw 'No targets are reachable over WinRM.' }

# ------------------------------------------------------------- payload -------
# Ship code and configuration only. Secrets, baselines, state and logs are
# per-host: copying this machine's secret store to another box would both break
# (DPAPI is machine-scoped) and needlessly duplicate credentials.
$include = @('lib', 'agents', 'scan', 'install', 'tools')
$excludeFiles = @('secrets.json', '.ngkey')

Write-Host '  Deploying...' -ForegroundColor Cyan
$results = @()

foreach ($target in $deployable) {
    $c = $target.computer
    if (-not $PSCmdlet.ShouldProcess($c, "Install NetGuard to $RemoteRoot and register scheduled tasks")) { continue }

    try {
        $session = New-PSSession -ComputerName $c -Credential $Credential -ErrorAction Stop

        Invoke-Command -Session $session -ScriptBlock {
            param($root)
            if (-not (Test-Path $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
            foreach ($d in 'lib', 'agents', 'scan', 'install', 'tools', 'config', 'state', 'logs', 'baseline', 'reports', 'quarantine', 'evidence', 'harden') {
                $p = Join-Path $root $d
                if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
            }
        } -ArgumentList $RemoteRoot

        $copied = 0
        foreach ($dir in $include) {
            $src = Join-Path $NGRoot $dir
            if (-not (Test-Path $src)) { continue }
            foreach ($f in (Get-ChildItem $src -File -Recurse)) {
                if ($excludeFiles -contains $f.Name) { continue }
                $rel = $f.FullName.Substring($NGRoot.Length).TrimStart('\')
                $dest = Join-Path $RemoteRoot $rel
                Copy-Item -Path $f.FullName -Destination $dest -ToSession $session -Force
                $copied++
            }
        }
        Write-Host ("    {0,-18} copied {1} file(s)" -f $c, $copied) -ForegroundColor DarkGray

        # Build the target's own config from ours, minus anything host-specific.
        $remoteCfg = $null
        if ($cfg) {
            $remoteCfg = $cfg | ConvertTo-Json -Depth 20 | ConvertFrom-Json
            $remoteCfg.host = $c
            $remoteCfg.remote = [pscustomobject]@{ hosts = @(); hubShare = $HubShare; role = 'spoke' }
            $remoteCfg.scan.watchPaths = @('C:\Users')   # resolved per-user on the target
        }

        Invoke-Command -Session $session -ScriptBlock {
            param($root, $cfgJson, $hub)
            $cfgPath = Join-Path $root 'config\netguard.config.json'
            if ($cfgJson) { Set-Content -LiteralPath $cfgPath -Value $cfgJson -Encoding utf8 }
            if ($hub) { Set-Content -LiteralPath (Join-Path $root 'config\hub.txt') -Value $hub -Encoding utf8 }
        } -ArgumentList $RemoteRoot, $(if ($remoteCfg) { $remoteCfg | ConvertTo-Json -Depth 20 } else { $null }), $HubShare

        Write-Host ("    {0,-18} configuration written" -f $c) -ForegroundColor DarkGray
        Write-Warning "    $c : secrets were NOT copied. DPAPI blobs are machine-scoped and cannot be decrypted elsewhere."
        Write-Host ("    {0,-18} run Setup-NetGuard.ps1 on that host to set its webhook and SMTP credentials." -f '') -ForegroundColor Yellow

        if (-not $NoTasks) {
            $taskResult = Invoke-Command -Session $session -ScriptBlock {
                param($root)
                try {
                    & (Join-Path $root 'install\Register-Tasks.ps1') -NoWatcher 2>&1 | Out-String
                }
                catch { "task registration failed: $($_.Exception.Message)" }
            } -ArgumentList $RemoteRoot
            if ($taskResult -match 'not configured yet') {
                Write-Host ("    {0,-18} tasks deferred until Setup-NetGuard.ps1 runs there" -f $c) -ForegroundColor Yellow
            }
            else {
                Write-Host ("    {0,-18} scheduled tasks registered" -f $c) -ForegroundColor Green
            }
        }

        Remove-PSSession $session
        $results += [pscustomobject]@{ computer = $c; status = 'deployed'; files = $copied }
    }
    catch {
        Write-Host ("    {0,-18} FAILED: {1}" -f $c, $_.Exception.Message) -ForegroundColor Red
        $results += [pscustomobject]@{ computer = $c; status = 'failed'; error = $_.Exception.Message }
    }
}

# Record the fleet so future runs need no arguments.
if ($cfg) {
    $cfg.remote = [pscustomobject]@{
        hosts    = @($ComputerName)
        hubShare = $HubShare
        role     = 'hub'
    }
    Save-NGConfig -Config $cfg | Out-Null
}

Write-Host ''
Write-Host '  Deployment summary' -ForegroundColor Cyan
$results | Format-Table -AutoSize
Write-Host '  On each target, run this once to finish setup:' -ForegroundColor White
Write-Host "    $RemoteRoot\Setup-NetGuard.ps1" -ForegroundColor Yellow
Write-Host ''
$results
