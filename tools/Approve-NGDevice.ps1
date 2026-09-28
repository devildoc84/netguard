<#
.SYNOPSIS
    List LAN devices and approve them into the baseline.

.DESCRIPTION
    New-device alerts are only useful if approving a device is easy - otherwise
    you learn to ignore them, which is worse than not having the alert.

    Run with no arguments to see everything currently on the network and whether
    it is already known.

.PARAMETER Mac
    Approve one or more devices by MAC address.

.PARAMETER Label
    A friendly name recorded alongside the approval, so next month you still know
    what "b8:27:eb:11:22:33" was.

.PARAMETER ApproveAll
    Approve everything currently visible. Convenient at first install; only do
    this when you are confident the network is clean.

.PARAMETER Forget
    Remove a MAC from the baseline so it alerts again if it reappears.

.EXAMPLE
    .\Approve-NGDevice.ps1

.EXAMPLE
    .\Approve-NGDevice.ps1 -Mac 6C:55:B1:E3:26:8F -Label "Living room TV"

.EXAMPLE
    .\Approve-NGDevice.ps1 -ApproveAll
#>
[CmdletBinding(DefaultParameterSetName = 'List')]
param(
    [Parameter(ParameterSetName = 'Approve', Mandatory = $true)][string[]]$Mac,
    [Parameter(ParameterSetName = 'Approve')][string]$Label,
    [Parameter(ParameterSetName = 'All', Mandatory = $true)][switch]$ApproveAll,
    [Parameter(ParameterSetName = 'Forget', Mandatory = $true)][string[]]$Forget,
    [switch]$Rescan
)

$NGRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $NGRoot 'lib/NetGuard.Platform.psm1') -DisableNameChecking -Global
Import-NGStack | Out-Null

function Get-Approved {
    $b = Get-NGBaseline -Name 'lan-devices'
    if ($null -eq $b) { return @() }
    @($b)
}
function Normalize { param($m) ($m -replace '[-:\.]', '').ToUpper() }

$approved = Get-Approved
$approvedMacs = @{}
foreach ($a in $approved) { if ($a.mac) { $approvedMacs[(Normalize $a.mac)] = $a } }

switch ($PSCmdlet.ParameterSetName) {

    'Forget' {
        $keep = @($approved | Where-Object { (Normalize $_.mac) -notin @($Forget | ForEach-Object { Normalize $_ }) })
        $removed = (Get-NGCount $approved) - (Get-NGCount $keep)
        Set-NGBaseline -Name 'lan-devices' -Value $keep
        Write-Host ''
        Write-Host "  Removed $removed device(s) from the baseline. They will alert again if seen." -ForegroundColor Yellow
        Write-Host ''
        return
    }

    'Approve' {
        $current = @(Get-NGLanDevices -SkipSweep:(-not $Rescan))
        $added = 0
        foreach ($m in $Mac) {
            $n = Normalize $m
            if ($approvedMacs.ContainsKey($n)) { Write-Host "  already approved: $m" -ForegroundColor DarkGray; continue }
            $found = @($current | Where-Object { (Normalize $_.mac) -eq $n })
            $entry = if ($found) { $found[0] } else {
                [pscustomobject][ordered]@{
                    mac = ($m -replace '-', ':').ToUpper(); ipAddress = 'not currently present'
                    hostName = $null; vendor = (Get-NGVendorFromMac $m); state = 'manual'
                    isGateway = $false
                    firstSeen = (Get-Date).ToUniversalTime().ToString('o')
                    lastSeen = (Get-Date).ToUniversalTime().ToString('o')
                }
            }
            $entry | Add-Member -NotePropertyName label -NotePropertyValue $Label -Force
            $entry | Add-Member -NotePropertyName approvedAt -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
            $approved += $entry
            $added++
            Write-Host "  approved: $($entry.mac)  $($entry.vendor)  $(if ($Label) { "[$Label]" })" -ForegroundColor Green
        }
        Set-NGBaseline -Name 'lan-devices' -Value $approved
        Write-Host ''
        Write-Host "  $added device(s) added to the baseline." -ForegroundColor Cyan
        Write-Host ''
        return
    }

    'All' {
        $current = @(Get-NGLanDevices -SkipSweep:(-not $Rescan))
        $new = @($current | Where-Object { -not $approvedMacs.ContainsKey((Normalize $_.mac)) })
        foreach ($d in $new) {
            $d | Add-Member -NotePropertyName approvedAt -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
        }
        $merged = @($approved) + @($new)
        Set-NGBaseline -Name 'lan-devices' -Value $merged
        Write-Host ''
        Write-Host "  Approved $(Get-NGCount $new) new device(s); baseline now holds $(Get-NGCount $merged)." -ForegroundColor Cyan
        foreach ($d in $new) { Write-Host "    $($d.ipAddress)  $($d.mac)  $($d.vendor)" -ForegroundColor DarkGray }
        Write-Host ''
        return
    }

    default {
        Write-Host ''
        Write-Host '  Scanning the LAN...' -ForegroundColor Cyan
        $current = @(Get-NGLanDevices)
        Write-Host ''
        if ((Get-NGCount $current) -eq 0) {
            Write-Host '  No devices found. Check that a physical network adapter has a gateway.' -ForegroundColor Yellow
            return
        }
        $rows = foreach ($d in ($current | Sort-Object { [version]$_.ipAddress } -ErrorAction SilentlyContinue)) {
            $known = $approvedMacs.ContainsKey((Normalize $d.mac))
            [pscustomobject]@{
                Status   = if ($known) { 'known' } else { 'NEW' }
                IP       = $d.ipAddress
                MAC      = $d.mac
                Hostname = if ($d.hostName) { $d.hostName } else { '-' }
                Vendor   = $d.vendor
                Label    = if ($known -and $approvedMacs[(Normalize $d.mac)].PSObject.Properties['label']) {
                    $approvedMacs[(Normalize $d.mac)].label
                } else { '' }
                Note     = if ($d.isGateway) { 'gateway' } else { '' }
            }
        }
        $rows | Format-Table -AutoSize
        $newCount = (Get-NGCount @($rows | Where-Object { $_.Status -eq 'NEW' }))
        if ($newCount -gt 0) {
            Write-Host "  $newCount device(s) are not in the baseline and will alert." -ForegroundColor Yellow
            Write-Host '  Approve one:   .\Approve-NGDevice.ps1 -Mac <MAC> -Label "what it is"' -ForegroundColor DarkGray
            Write-Host '  Approve all:   .\Approve-NGDevice.ps1 -ApproveAll' -ForegroundColor DarkGray
        }
        else {
            Write-Host '  Every visible device is already in the baseline.' -ForegroundColor Green
        }
        Write-Host ''
    }
}
