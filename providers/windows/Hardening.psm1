<#
    Windows control catalogue and Windows-specific posture rules.

    Two things live here because both are "knowledge about Windows security
    policy" rather than engine logic:

      Get-NGHardeningChecks          the tiered control catalogue (data, not code)
      Find-NGPlatformPostureFindings Windows-only detections the shared rules
                                     cannot express

    The audit engine, scoring and script generation are platform-neutral and
    live in lib/NetGuard.Harden.psm1.

    TIERS
      1  Safe. No user-visible impact expected on a normal workstation.
      2  Moderate. Can break legacy SMB devices, old printers, some VPN clients.
      3  Aggressive. Enterprise-grade. Ships in AUDIT mode first, deliberately.
#>

function Get-NGRemediationPreamble {
    <#
        Prepended to every generated Apply script. Windows gets a System Restore
        checkpoint, which recovers the registry-level changes even if the paired
        Rollback script cannot run.
    #>
    @'
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Continue'

# A restore point makes registry changes recoverable even if Rollback fails.
try {
    Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
    Checkpoint-Computer -Description "NetGuard hardening" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
    Write-Host "Restore point created." -ForegroundColor Green
} catch {
    Write-Warning "Could not create a restore point: $($_.Exception.Message)"
    # Windows rate-limits restore points to one per 24h by default.
    $go = Read-Host "Continue without one? (yes/no)"
    if ($go -ne 'yes') { exit 1 }
}
'@
}

function Get-NGHardeningChecks {
    [CmdletBinding()]
    param()
    @(
        # ----------------------------------------------------------- TIER 1 ----
        [pscustomobject]@{
            Id = 'WIN-ASR-CORE'; Tier = 1; Weight = 12; Category = 'Attack Surface Reduction'
            Title = 'Enable the core ASR rule set in Block mode'
            Rationale = 'ASR rules block whole exploit classes rather than individual files: Office spawning children, obfuscated scripts, executables from email or USB, credential theft from LSASS, and abuse of WMI/PSExec for lateral movement. Free, built in, and normally the largest single risk reduction available on Windows.'
            Risk = 'Low. The set chosen here excludes the rules known to cause false positives with developer tooling and installers.'
            Test = {
                $pref = Get-MpPreference
                $acts = ConvertTo-NGArray $pref.AttackSurfaceReductionRules_Actions
                (Get-NGCount @($acts | Where-Object { (Get-NGSafeInt $_) -eq 1 })) -ge 8
            }
            Apply = @'
$rules = @{
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Block Office apps creating child processes'
    '3B576869-A4EC-4529-8536-B80A7769E899' = 'Block Office apps creating executable content'
    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Block Office apps injecting into other processes'
    'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Block JS/VBS launching downloaded executable content'
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Block obfuscated scripts'
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Office comms apps creating child processes'
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Block credential stealing from LSASS'
    'D1E49AAC-8F56-4280-B9BA-993A6D77406C' = 'Block process creation from PSExec/WMI'
    'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Block untrusted/unsigned processes from USB'
    '26190899-1602-49E8-8B27-EB1D0A1CE869' = 'Block Office comms child process creation'
    '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' = 'Block Adobe Reader creating child processes'
    'E6DB77E5-3DF2-4CF1-B95A-636979351E5B' = 'Block persistence through WMI event subscription'
}
foreach ($rid in $rules.Keys) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rid -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Continue
    Write-Host ('  enabled: ' + $rules[$rid])
}
'@
            Rollback = @'
$rules = @('D4F940AB-401B-4EFC-AADC-AD5F3C50688A','3B576869-A4EC-4529-8536-B80A7769E899',
           '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84','D3E037E1-3EB8-44C8-A917-57927947596D',
           '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC','92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B',
           '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2','D1E49AAC-8F56-4280-B9BA-993A6D77406C',
           'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4','26190899-1602-49E8-8B27-EB1D0A1CE869',
           '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C','E6DB77E5-3DF2-4CF1-B95A-636979351E5B')
foreach ($rid in $rules) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $rid -ErrorAction Continue }
'@
        }
        [pscustomobject]@{
            Id = 'WIN-NETPROT'; Tier = 1; Weight = 8; Category = 'Antivirus'
            Title = 'Enable Network Protection'
            Rationale = 'Blocks outbound connections to known-malicious hosts for every process on the machine, not just browsers. Catches malware that never opens a browser at all.'
            Risk = 'Low. Occasionally blocks newly-registered or security-research domains; per-URL exclusions are possible.'
            Test = { (Get-NGSafeInt (Get-MpPreference).EnableNetworkProtection) -eq 1 }
            Apply = 'Set-MpPreference -EnableNetworkProtection Enabled'
            Rollback = 'Set-MpPreference -EnableNetworkProtection Disabled'
        }
        [pscustomobject]@{
            Id = 'WIN-MAPS'; Tier = 1; Weight = 6; Category = 'Antivirus'
            Title = 'Enable cloud-delivered protection and sample submission'
            Rationale = 'Cloud protection blocks brand-new threats in seconds instead of waiting for the next signature push. Sample submission is what makes that work for files nobody has seen before.'
            Risk = 'Low. Sends suspicious file metadata and sometimes files to Microsoft. Set SubmitSamplesConsent to 1 to be prompted instead.'
            Test = { (Get-NGSafeInt (Get-MpPreference).MAPSReporting) -eq 2 }
            Apply = "Set-MpPreference -MAPSReporting Advanced`nSet-MpPreference -SubmitSamplesConsent SendSafeSamples"
            Rollback = 'Set-MpPreference -MAPSReporting Disabled'
        }
        [pscustomobject]@{
            Id = 'WIN-PUA'; Tier = 1; Weight = 4; Category = 'Antivirus'
            Title = 'Enable PUA (potentially unwanted application) protection'
            Rationale = 'Blocks adware, bundleware and cryptominers that are not technically malware but behave like it.'
            Risk = 'Low. Can flag aggressive installers and some game mod tools.'
            Test = { (Get-NGSafeInt (Get-MpPreference).PUAProtection) -eq 1 }
            Apply = 'Set-MpPreference -PUAProtection Enabled'
            Rollback = 'Set-MpPreference -PUAProtection Disabled'
        }
        [pscustomobject]@{
            Id = 'WIN-FW-LOG'; Tier = 1; Weight = 7; Category = 'Firewall'
            Title = 'Enable firewall drop logging on all profiles'
            Rationale = 'Without dropped-packet logs there is no record of anything probing this host - a blind spot directly at the network edge where monitoring matters most.'
            Risk = 'None. Writes to a capped 16 MB log file.'
            Test = { (Get-NGCount @(Get-NetFirewallProfile | Where-Object { $_.LogBlocked -ne 'True' })) -eq 0 }
            Apply = @'
foreach ($prof in 'Domain','Private','Public') {
    Set-NetFirewallProfile -Profile $prof -LogBlocked True -LogAllowed False `
        -LogMaxSizeKilobytes 16384 `
        -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
}
'@
            Rollback = "foreach (`$prof in 'Domain','Private','Public') { Set-NetFirewallProfile -Profile `$prof -LogBlocked False }"
        }
        [pscustomobject]@{
            Id = 'WIN-FW-INBOUND'; Tier = 1; Weight = 6; Category = 'Firewall'
            Title = 'Explicitly set default inbound action to Block'
            Rationale = 'NotConfigured happens to resolve to Block today, but it is an implicit default rather than stated policy, so it can change under a policy refresh or a third-party tool without anyone noticing.'
            Risk = 'None. This makes the current effective behaviour explicit.'
            Test = { (Get-NGCount @(Get-NetFirewallProfile | Where-Object { $_.DefaultInboundAction -ne 'Block' })) -eq 0 }
            Apply = "foreach (`$prof in 'Domain','Private','Public') { Set-NetFirewallProfile -Profile `$prof -DefaultInboundAction Block -DefaultOutboundAction Allow }"
            Rollback = "foreach (`$prof in 'Domain','Private','Public') { Set-NetFirewallProfile -Profile `$prof -DefaultInboundAction NotConfigured }"
        }
        [pscustomobject]@{
            Id = 'WIN-PSLOG'; Tier = 1; Weight = 9; Category = 'Logging'
            Title = 'Enable PowerShell script block logging'
            Rationale = 'Records the actual deobfuscated code PowerShell runs. Without it NetGuard can see that PowerShell ran but not what it did, and obfuscated one-liners are the most common attack delivery method on Windows.'
            Risk = 'Low. Verbose logs; the event log is capped. Secrets typed into a console may be recorded, so treat the log as sensitive.'
            Test = { 1 -eq (Get-NGSafeInt (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging) }
            Apply = @'
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1 -Type DWord
$m = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path $m -Force | Out-Null
Set-ItemProperty -Path $m -Name EnableModuleLogging -Value 1 -Type DWord
New-Item -Path "$m\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$m\ModuleNames" -Name '*' -Value '*'
'@
            Rollback = @'
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -ErrorAction SilentlyContinue
'@
        }
        [pscustomobject]@{
            Id = 'WIN-CMDLINE'; Tier = 1; Weight = 8; Category = 'Logging'
            Title = 'Audit process creation including command lines'
            Rationale = 'Event 4688 without the command line tells you a process started but not what it was asked to do, which is usually the only part that matters for triage.'
            Risk = 'Low. More Security log volume; command lines may contain secrets.'
            Test = { 1 -eq (Get-NGSafeInt (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled) }
            Apply = @'
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
'@
            Rollback = @'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 0 -Type DWord -ErrorAction SilentlyContinue
auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable | Out-Null
'@
        }
        [pscustomobject]@{
            Id = 'WIN-LOGSIZE'; Tier = 1; Weight = 5; Category = 'Logging'
            Title = 'Increase Security and PowerShell log sizes'
            Rationale = 'Default log sizes roll over in hours on a busy host, so by the time you investigate the evidence is gone. Retention is what makes detection useful after the fact.'
            Risk = 'None beyond disk usage (about 600 MB total).'
            Test = { (Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue).MaximumSizeInBytes -ge 268435456 }
            Apply = @'
wevtutil sl Security /ms:268435456
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:134217728
wevtutil sl System /ms:134217728
wevtutil sl Application /ms:67108864
'@
            Rollback = @'
wevtutil sl Security /ms:20971520
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:15728640
'@
        }
        [pscustomobject]@{
            Id = 'WIN-LLMNR'; Tier = 1; Weight = 7; Category = 'Network'
            Title = 'Disable LLMNR and mDNS name resolution'
            Rationale = 'LLMNR broadcasts name lookups to the entire subnet and lets anything on it answer. This is the basis of Responder-style credential theft and requires no vulnerability to exploit.'
            Risk = 'Low. Windows falls back to DNS. Some peer discovery and older printer sharing needs mDNS; revert that half if local discovery breaks.'
            Test = { 0 -eq (Get-NGSafeInt (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast -Default 1) }
            Apply = @'
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name EnableMulticast -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS -Value 0 -Type DWord -ErrorAction SilentlyContinue
'@
            Rollback = @'
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS -ErrorAction SilentlyContinue
'@
        }
        [pscustomobject]@{
            Id = 'WIN-WDIGEST'; Tier = 1; Weight = 10; Category = 'Credentials'
            Title = 'Ensure WDigest cannot cache cleartext credentials'
            Rationale = 'UseLogonCredential=1 forces Windows to keep plaintext passwords in LSASS memory, which is exactly what credential dumpers harvest. Nothing has needed this since Server 2008 R2.'
            Risk = 'None on any supported system.'
            Test = { 0 -eq (Get-NGSafeInt (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential -Default 0) }
            Apply = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 0 -Type DWord"
            Rollback = "# Intentionally NOT reversible: restoring this would re-enable cleartext credential caching.`nWrite-Host 'WDigest cleartext caching is not re-enabled by rollback, by design.'"
        }
        [pscustomobject]@{
            Id = 'WIN-AUTORUN'; Tier = 1; Weight = 4; Category = 'Network'
            Title = 'Disable AutoRun and AutoPlay on all drive types'
            Rationale = 'Stops removable media executing content on insertion, still a live infection path for USB-borne worms.'
            Risk = 'Low. You will open removable drives manually.'
            Test = { 255 -eq (Get-NGSafeInt (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun) }
            Apply = @'
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name NoDriveTypeAutoRun -Value 255 -Type DWord
Set-ItemProperty -Path $k -Name NoAutorun -Value 1 -Type DWord
'@
            Rollback = @'
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoAutorun -ErrorAction SilentlyContinue
'@
        }
        [pscustomobject]@{
            Id = 'WIN-INSTALLER'; Tier = 1; Weight = 9; Category = 'Privilege'
            Title = 'Ensure AlwaysInstallElevated is disabled'
            Rationale = 'When enabled, any user can install an MSI as SYSTEM. A textbook local privilege escalation with no legitimate workstation use.'
            Risk = 'None.'
            Test = {
                $a = Get-NGSafeInt (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated -Default 0
                $b = Get-NGSafeInt (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated -Default 0
                ($a -ne 1) -and ($b -ne 1)
            }
            Apply = @'
foreach ($hive in 'HKLM','HKCU') {
    $k = "${hive}:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    if (Test-Path $k) { Set-ItemProperty -Path $k -Name AlwaysInstallElevated -Value 0 -Type DWord -ErrorAction SilentlyContinue }
}
'@
            Rollback = '# Intentionally NOT reversible: re-enabling AlwaysInstallElevated is a privilege escalation.'
        }

        # ----------------------------------------------------------- TIER 2 ----
        [pscustomobject]@{
            Id = 'WIN-CFA'; Tier = 2; Weight = 9; Category = 'Antivirus'
            Title = 'Enable Controlled Folder Access (audit first)'
            Rationale = 'CFA is the built-in anti-ransomware control: it stops untrusted processes writing to Documents, Pictures and similar folders. Applied in AuditMode here so you can see what it would block before it blocks anything.'
            Risk = 'Moderate once enforcing. Games with custom save paths, backup tools and editors commonly need an allowlist entry. Audit mode has no impact.'
            Test = { (Get-NGSafeInt (Get-MpPreference).EnableControlledFolderAccess) -in @(1, 2) }
            Apply = @'
# AuditMode logs what WOULD be blocked without blocking it. Review Defender
# Operational events 1123/1124 for a week, allow what you recognise, then enforce.
Set-MpPreference -EnableControlledFolderAccess AuditMode
Write-Host 'CFA is in AUDIT mode. To enforce: Set-MpPreference -EnableControlledFolderAccess Enabled'
'@
            Rollback = 'Set-MpPreference -EnableControlledFolderAccess Disabled'
        }
        [pscustomobject]@{
            Id = 'WIN-LSAPPL'; Tier = 2; Weight = 10; Category = 'Credentials'
            Title = 'Run LSASS as a protected process (RunAsPPL)'
            Rationale = 'Prevents ordinary admin-level tools from opening LSASS memory, defeating the most common credential-dumping path outright.'
            Risk = 'Moderate. Blocks anything that legitimately reads LSASS - some older AV, smartcard middleware, debuggers. Requires a reboot.'
            Test = { 1 -eq (Get-NGSafeInt (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL) }
            Apply = @'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPLBoot -Value 1 -Type DWord -ErrorAction SilentlyContinue
Write-Host 'RunAsPPL takes effect after a REBOOT.'
'@
            Rollback = @'
Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPLBoot -ErrorAction SilentlyContinue
'@
        }
        [pscustomobject]@{
            Id = 'WIN-SMBSIGN'; Tier = 2; Weight = 7; Category = 'SMB'
            Title = 'Require SMB signing on client and server'
            Rationale = 'Without required signing, SMB sessions can be relayed and tampered with by anything on the same network segment. This is what makes NTLM relay attacks work.'
            Risk = 'Moderate. Older NAS units, printers and media servers that do not support signing will stop connecting. Test those first.'
            Test = {
                $s = Get-SmbServerConfiguration; $c = Get-SmbClientConfiguration
                ($s.RequireSecuritySignature -eq $true) -and ($c.RequireSecuritySignature -eq $true)
            }
            Apply = @'
Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
'@
            Rollback = @'
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
'@
        }
        [pscustomobject]@{
            Id = 'WIN-NOSMB1'; Tier = 2; Weight = 10; Category = 'SMB'
            Title = 'Remove SMBv1 entirely'
            Rationale = 'SMBv1 is the protocol WannaCry and NotPetya spread over. It has no legitimate use unless you own a device from before 2008 that cannot be replaced.'
            Risk = 'Moderate only if you have genuinely ancient network storage. Otherwise none.'
            Test = { -not (Get-SmbServerConfiguration).EnableSMB1Protocol }
            Apply = @'
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
'@
            Rollback = 'Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null'
        }
        [pscustomobject]@{
            Id = 'WIN-NETBIOS'; Tier = 2; Weight = 6; Category = 'Network'
            Title = 'Disable NetBIOS over TCP/IP on all adapters'
            Rationale = 'NetBIOS name service is broadcast-based and spoofable in the same way as LLMNR, and it keeps port 139 listening on every interface.'
            Risk = 'Moderate. Breaks browsing by legacy NetBIOS name. Modern name resolution and SMB over 445 are unaffected.'
            Test = {
                $adapters = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
                (Get-NGCount @($adapters | Where-Object { 2 -ne (Get-NGSafeInt (Get-ItemProperty $_.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions) })) -eq 0
            }
            Apply = @'
# NetbiosOptions: 0 = DHCP default, 1 = enable, 2 = disable
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 -Type DWord -ErrorAction SilentlyContinue
}
'@
            Rollback = @'
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 0 -Type DWord -ErrorAction SilentlyContinue
}
'@
        }
        [pscustomobject]@{
            Id = 'WIN-UAC'; Tier = 2; Weight = 7; Category = 'Privilege'
            Title = 'Require UAC consent on the secure desktop for admins'
            Rationale = 'The default admin consent behaviour auto-elevates signed Windows binaries without prompting, which several UAC bypasses rely on. Prompting on the secure desktop also prevents a malicious process faking the dialog.'
            Risk = 'Moderate. Noticeably more UAC prompts during software installation.'
            Test = {
                $c = Get-NGSafeInt (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
                $s = Get-NGSafeInt (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -ErrorAction SilentlyContinue).PromptOnSecureDesktop
                ($c -eq 2) -and ($s -eq 1)
            }
            Apply = @'
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty -Path $k -Name ConsentPromptBehaviorAdmin -Value 2 -Type DWord
Set-ItemProperty -Path $k -Name PromptOnSecureDesktop -Value 1 -Type DWord
Set-ItemProperty -Path $k -Name EnableLUA -Value 1 -Type DWord
Set-ItemProperty -Path $k -Name FilterAdministratorToken -Value 1 -Type DWord
'@
            Rollback = @'
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty -Path $k -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord
Set-ItemProperty -Path $k -Name FilterAdministratorToken -Value 0 -Type DWord
'@
        }

        # ----------------------------------------------------------- TIER 3 ----
        [pscustomobject]@{
            Id = 'WIN-CREDGUARD'; Tier = 3; Weight = 8; Category = 'Credentials'
            Title = 'Enable Credential Guard'
            Rationale = 'Isolates derived credentials in a virtualisation-based container so even SYSTEM cannot extract NTLM hashes or Kerberos tickets from LSASS.'
            Risk = 'High if you run desktop hypervisors. Credential Guard uses the hypervisor and commonly conflicts with VMware Workstation and VirtualBox.'
            Test = {
                $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
                @($dg.SecurityServicesRunning) -contains 1
            }
            Apply = @'
Write-Warning 'Credential Guard commonly breaks VMware Workstation and VirtualBox.'
Write-Warning 'Verify your VMs still boot after the reboot, and roll back if not.'
$k = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name EnableVirtualizationBasedSecurity -Value 1 -Type DWord
Set-ItemProperty -Path $k -Name RequirePlatformSecurityFeatures -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LsaCfgFlags -Value 1 -Type DWord
Write-Host 'Reboot required.'
'@
            Rollback = @'
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LsaCfgFlags -Value 0 -Type DWord -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue
Write-Host 'Reboot required.'
'@
        }
        [pscustomobject]@{
            Id = 'WIN-APPLOCKER'; Tier = 3; Weight = 10; Category = 'Application Control'
            Title = 'Deploy AppLocker in audit mode'
            Rationale = 'Application control is the strongest single control against unknown malware because it inverts the model: instead of blocking known-bad, only known-good runs. Audit mode builds the evidence for a future enforcing policy without blocking anything.'
            Risk = 'Audit mode is safe. Never enforce a policy you have not reviewed for a full week - enforcing a bad one makes the machine unusable.'
            Test = {
                $pol = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
                $null -ne $pol -and $pol.RuleCollections.Count -gt 0
            }
            Apply = @'
$svc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
if ($svc) { Set-Service AppIDSvc -StartupType Automatic; Start-Service AppIDSvc -ErrorAction SilentlyContinue }
$xml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="Windows" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="All (audit)" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="AuditOnly">
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d" Name="All scripts (audit)" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@
$tmp = Join-Path $env:TEMP 'netguard-applocker-audit.xml'
Set-Content -LiteralPath $tmp -Value $xml -Encoding utf8
Set-AppLockerPolicy -XmlPolicy $tmp -Merge
Remove-Item $tmp -Force
Write-Host 'AppLocker deployed in AUDIT mode. Review events for a week before enforcing.'
'@
            Rollback = @'
$empty = Join-Path $env:TEMP 'netguard-applocker-empty.xml'
Set-Content -LiteralPath $empty -Value '<AppLockerPolicy Version="1"></AppLockerPolicy>' -Encoding utf8
Set-AppLockerPolicy -XmlPolicy $empty
Remove-Item $empty -Force
Set-Service AppIDSvc -StartupType Manual -ErrorAction SilentlyContinue
'@
        }
        [pscustomobject]@{
            Id = 'WIN-NOPSV2'; Tier = 3; Weight = 6; Category = 'Application Control'
            Title = 'Disable the PowerShell v2 engine'
            Rationale = 'PowerShell 2.0 predates AMSI, script block logging and transcription, so invoking it with -Version 2 bypasses every PowerShell-based detection this system relies on.'
            Risk = 'Low in practice. Only affects software explicitly requesting the v2 engine.'
            Test = {
                $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
                $null -eq $f -or $f.State -ne 'Enabled'
            }
            Apply = @'
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction SilentlyContinue | Out-Null
'@
            Rollback = 'Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null'
        }
    )
}

# ============================================ WINDOWS-SPECIFIC DETECTIONS ====

function Find-NGPlatformPostureFindings {
    <#
        Windows detections the cross-platform rules cannot express. The shared
        engine handles antivirus health, firewall state, disk encryption,
        patching, logging and uptime; everything here is Windows-only.

        Tri-state discipline applies throughout: test -eq $false, never -not $x,
        so unreadable data stays silent instead of raising a false alarm.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Posture)
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'posture-windows'
    $raw = $Posture.raw

    # ---------------- Defender hardening features
    $dp = $raw.defender
    if ($dp) {
        if ([int]$dp.asrRuleCount -eq 0) {
            $f.Add((New-NGFinding -Category 'Hardening' -Severity 'High' -Agent $agentId `
                        -Title 'No Attack Surface Reduction rules are configured' `
                        -Detail 'ASR rules block entire exploit classes rather than specific files: Office spawning child processes, obfuscated scripts, credential theft from LSASS, executables arriving by email or USB. They are free, built in, and typically the largest single risk reduction available on a Windows host.' `
                        -Recommendation 'Run harden\Apply-Tier1.ps1, which enables the low-breakage-risk ASR set in Block mode.' `
                        -Evidence @{ asrRuleCount = 0 } -FingerprintSeed 'asr-none'))
        }
        elseif ([int]$dp.asrBlockModeCount -eq 0) {
            $f.Add((New-NGFinding -Category 'Hardening' -Severity 'Medium' -Agent $agentId `
                        -Title 'ASR rules exist but none are in Block mode' `
                        -Detail 'Rules in Audit mode log but do not prevent. Audit is the right first step; leaving them there indefinitely provides visibility without protection.' `
                        -Recommendation 'Review ASR audit events, then promote clean rules to Block (action 1).' `
                        -Evidence $dp -FingerprintSeed 'asr-audit-only'))
        }
        if ([int]$dp.controlledFolderAccess -eq 0) {
            $f.Add((New-NGFinding -Category 'Hardening' -Severity 'Medium' -Agent $agentId `
                        -Title 'Controlled Folder Access is disabled' `
                        -Detail 'CFA stops untrusted processes writing to Documents, Pictures and other user data folders. It is the built-in anti-ransomware control.' `
                        -Recommendation 'Enable in Audit mode first (Set-MpPreference -EnableControlledFolderAccess AuditMode), review blocks for a week, then enforce.' `
                        -Evidence $dp -FingerprintSeed 'cfa-off'))
        }
        if ([int]$dp.networkProtection -eq 0) {
            $f.Add((New-NGFinding -Category 'Hardening' -Severity 'Medium' -Agent $agentId `
                        -Title 'Network Protection is disabled' `
                        -Detail 'Network Protection blocks outbound connections to known-malicious domains and IPs at the OS level, across every browser and every process - including malware that never touches a browser.' `
                        -Recommendation 'Set-MpPreference -EnableNetworkProtection Enabled' `
                        -Evidence $dp -FingerprintSeed 'netprotect-off'))
        }
        if ([int]$dp.cloudDeliveredProtection -eq 0) {
            $f.Add((New-NGFinding -Category 'Antivirus' -Severity 'Medium' -Agent $agentId `
                        -Title 'Cloud-delivered protection (MAPS) is off' `
                        -Detail 'Cloud protection is how Defender blocks brand-new threats within seconds instead of waiting for a signature push.' `
                        -Recommendation 'Set-MpPreference -MAPSReporting Advanced' `
                        -Evidence $dp -FingerprintSeed 'maps-off'))
        }
        if ($dp.exclusionsReadable -and [int]$dp.exclusionPathCount -gt 0) {
            $f.Add((New-NGFinding -Category 'Antivirus' -Severity 'Low' -Agent $agentId `
                        -Title "$($dp.exclusionPathCount) Defender exclusion path(s) configured" `
                        -Detail 'Exclusions are blind spots and a favourite persistence trick - malware adds one, then lives inside it. Worth confirming each was added deliberately.' `
                        -Recommendation 'Review: Get-MpPreference | Select -Expand ExclusionPath. Remove any you do not recognise, and prefer narrow process exclusions over broad directory ones.' `
                        -Evidence @{ paths = $dp.exclusionPaths; processes = $dp.exclusionProcesses } `
                        -FingerprintSeed ('defender-exclusions|' + ((@($dp.exclusionPaths) | Sort-Object) -join ';'))))
        }
        if ($dp.scanScriptsEnabled -eq $false) {
            $f.Add((New-NGFinding -Category 'Antivirus' -Severity 'High' -Agent $agentId `
                        -Title 'Defender script scanning is disabled' `
                        -Detail 'Script scanning is what inspects PowerShell, JScript and VBScript through AMSI. Disabling it is a common post-compromise action.' `
                        -Recommendation 'Set-MpPreference -DisableScriptScanning $false' `
                        -Evidence $dp -FingerprintSeed 'script-scan-off'))
        }
    }

    # ---------------- platform security
    $dg = $raw.deviceGuard
    if ($dg -and $dg.hvciRunning -eq $false) {
        $f.Add((New-NGFinding -Category 'Platform' -Severity 'Medium' -Agent $agentId `
                    -Title 'Memory integrity (HVCI) is not running' `
                    -Detail 'HVCI uses virtualisation to prevent unsigned or malicious kernel code from executing, which blocks the vulnerable-driver technique used by most modern EDR-killers.' `
                    -Recommendation 'Windows Security > Device security > Core isolation > Memory integrity. Some older VM and audio drivers are incompatible; the UI will name them.' `
                    -Evidence $dg -FingerprintSeed 'hvci-off'))
    }

    # ---------------- policies
    $po = $raw.policies
    if ($po) {
        if ((Get-NGSafeInt $po.uacEnabled -Default 1) -eq 0) {
            $f.Add((New-NGFinding -Category 'Hardening' -Severity 'Critical' -Agent $agentId `
                        -Title 'UAC is completely disabled' `
                        -Detail 'Every process started by an administrator account runs fully elevated with no prompt, removing the last barrier between a single click and full system compromise.' `
                        -Recommendation 'Set EnableLUA to 1 and reboot.' -Evidence $po -FingerprintSeed 'uac-off'))
        }
        if ((Get-NGSafeInt $po.wdigestUseLogonCredential -Default 0) -eq 1) {
            $f.Add((New-NGFinding -Category 'Credentials' -Severity 'Critical' -Agent $agentId `
                        -Title 'WDigest is storing cleartext passwords in memory' `
                        -Detail 'UseLogonCredential=1 forces Windows to keep plaintext credentials in LSASS, which is exactly what credential dumpers harvest. Windows has not needed this since 2008 R2, so its presence is either a very old compatibility hack or a deliberate attacker change.' `
                        -Recommendation 'Set UseLogonCredential to 0 and reboot. Treat as suspicious if you did not set it.' `
                        -Evidence $po -FingerprintSeed 'wdigest-cleartext'))
        }
        if ((Get-NGSafeInt $po.lsaRunAsPPL -Default 0) -ne 1) {
            $f.Add((New-NGFinding -Category 'Credentials' -Severity 'Medium' -Agent $agentId `
                        -Title 'LSASS is not running as a protected process (RunAsPPL)' `
                        -Detail 'RunAsPPL stops ordinary admin-level tools opening LSASS memory, which defeats the most common credential-dumping path.' `
                        -Recommendation 'Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 and reboot.' `
                        -Evidence $po -FingerprintSeed 'lsa-ppl-off'))
        }
        if ((Get-NGSafeInt $po.installElevatedAlways -Default 0) -eq 1) {
            $f.Add((New-NGFinding -Category 'Hardening' -Severity 'Critical' -Agent $agentId `
                        -Title 'AlwaysInstallElevated is enabled' `
                        -Detail 'Any user can install an MSI as SYSTEM. This is a textbook local privilege escalation with no legitimate use on a workstation.' `
                        -Recommendation 'Delete AlwaysInstallElevated under HKLM and HKCU \SOFTWARE\Policies\Microsoft\Windows\Installer.' `
                        -Evidence $po -FingerprintSeed 'always-install-elevated'))
        }
        if ((Get-NGSafeInt $po.llmnrEnableMulticast -Default 1) -ne 0) {
            $f.Add((New-NGFinding -Category 'Hardening' -Severity 'Medium' -Agent $agentId `
                        -Title 'LLMNR is enabled' `
                        -Detail 'LLMNR broadcasts name lookups to the whole subnet, and anything on that subnet can answer. This is the basis of Responder-style credential theft and needs no vulnerability to work.' `
                        -Recommendation 'Set EnableMulticast = 0 under HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient.' `
                        -Evidence $po -FingerprintSeed 'llmnr-on'))
        }
    }

    # ---------------- RDP
    if ($Posture.remoteAccess.rdp.enabled -eq $true) {
        $secure = ($Posture.remoteAccess.rdp.secure -eq $true)
        $sev = if ($secure) { 'Medium' } else { 'High' }
        $nla = if ($secure) { 'NLA enabled' } else { 'NLA NOT enabled' }
        $f.Add((New-NGFinding -Category 'Exposure' -Severity $sev -Agent $agentId `
                    -Title "RDP is enabled on this host ($nla)" `
                    -Detail 'RDP is the most common initial access vector for ransomware. On a LAN with NLA it is defensible; exposed to the internet it is not.' `
                    -Recommendation 'If you do not need RDP, set fDenyTSConnections = 1. If you do, require NLA, restrict the firewall rule to specific source IPs, and never port-forward 3389 - use a VPN.' `
                    -Evidence $Posture.remoteAccess.rdp -FingerprintSeed 'rdp-enabled'))
    }

    # ---------------- SMB
    if ($raw.smb) {
        if ($raw.smb.smb1Enabled -eq $true) {
            $f.Add((New-NGFinding -Category 'Hardening' -Severity 'Critical' -Agent $agentId `
                        -Title 'SMBv1 is enabled' `
                        -Detail 'SMBv1 is the protocol WannaCry and NotPetya spread over. It has no legitimate use unless you have a device from before 2008 that cannot be replaced.' `
                        -Recommendation 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' `
                        -Evidence $raw.smb -FingerprintSeed 'smb1-on'))
        }
        if ($raw.smb.requireSigning -eq $false) {
            $f.Add((New-NGFinding -Category 'Hardening' -Severity 'Medium' -Agent $agentId `
                        -Title 'SMB server signing is not required' `
                        -Detail 'Without required signing, SMB sessions can be relayed and tampered with by anything on the same network segment.' `
                        -Recommendation 'Set-SmbServerConfiguration -RequireSecuritySignature $true  (Tier 2 - test NAS and printer access afterwards).' `
                        -Evidence $raw.smb -FingerprintSeed 'smb-signing-off'))
        }
    }

    # ---------------- Windows Update service
    if ($raw.wuStartType -eq 'Disabled') {
        $f.Add((New-NGFinding -Category 'Patching' -Severity 'High' -Agent $agentId `
                    -Title 'Windows Update service is disabled' `
                    -Detail 'This host will receive no security patches at all. Disabling wuauserv is also a known malware persistence tactic.' `
                    -Recommendation 'Set-Service wuauserv -StartupType Manual' `
                    -Evidence @{ startType = $raw.wuStartType } -FingerprintSeed 'wu-disabled'))
    }

    , @($f)
}

Export-ModuleMember -Function *
