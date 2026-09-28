<#
    Linux control catalogue and Linux-specific posture rules.

    Derived from the CIS Distribution Independent Linux Benchmark and the common
    ground between the Debian/Ubuntu and RHEL hardening guides, trimmed to what
    is meaningful on a single workstation or small server.

    TIERS
      1  Safe. No user-visible impact expected.
      2  Moderate. Can break remote access habits, legacy NFS/Samba clients, or
         containers that rely on permissive kernel settings.
      3  Aggressive. Enterprise-grade. Ships in audit/complain mode first.

    A note on Apply blocks: these run under pwsh, so they shell out for the
    actual system changes. Each is written to be idempotent - running Apply twice
    must not produce a different result than running it once, because the
    hardening agent regenerates these scripts daily and people re-run them.
#>

function Get-NGRemediationPreamble {
    <#
        Prepended to every generated Apply script.

        Linux has no System Restore, so the equivalent safety net is a timestamped
        backup of every config file the scripts touch. Rollback scripts restore
        from it.
    #>
    @'
$ErrorActionPreference = 'Continue'

if ((id -u) -ne '0') {
    Write-Host 'This script must run as root:  sudo pwsh ./harden/Apply-Tier1.ps1' -ForegroundColor Red
    exit 1
}

# Linux has no System Restore. Back up every config these scripts touch instead,
# so a rollback has something authoritative to restore from.
$backupDir = "/var/backups/netguard/$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
foreach ($cfg in '/etc/ssh/sshd_config', '/etc/sysctl.conf', '/etc/login.defs',
                 '/etc/audit/rules.d/audit.rules', '/etc/fstab', '/etc/sudoers') {
    if (Test-Path $cfg) { Copy-Item $cfg "$backupDir/" -Force -ErrorAction SilentlyContinue }
}
if (Test-Path '/etc/sysctl.d') { Copy-Item '/etc/sysctl.d' "$backupDir/sysctl.d" -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host "Config backup: $backupDir" -ForegroundColor Green
Set-Content -LiteralPath '/var/backups/netguard/latest' -Value $backupDir
'@
}

function Get-NGHardeningChecks {
    [CmdletBinding()]
    param()
    @(
        # ----------------------------------------------------------- TIER 1 ----
        [pscustomobject]@{
            Id = 'LNX-AUTOUPDATE'; Tier = 1; Weight = 10; Category = 'Patching'
            Title = 'Enable unattended security updates'
            Rationale = 'Most Linux compromises on small deployments are unpatched public vulnerabilities in an internet-facing service, not novel malware. Automatic security updates close that window without anyone remembering to log in.'
            Risk = 'Low. Security-only updates rarely change behaviour. Services are not auto-restarted unless you enable that separately.'
            Test = {
                $apt = Get-NGFileTextSafe '/etc/apt/apt.conf.d/20auto-upgrades'
                if ($apt) { return ($apt -match 'Unattended-Upgrade"?\s+"1"') }
                $dnf = Invoke-NGCommand -FilePath 'systemctl' -Arguments @('is-enabled', 'dnf-automatic.timer')
                ($dnf.stdout.Trim() -eq 'enabled')
            }
            Apply = @'
if (Get-Command apt-get -ErrorAction SilentlyContinue) {
    apt-get install -y unattended-upgrades
    Set-Content -LiteralPath '/etc/apt/apt.conf.d/20auto-upgrades' -Value @"
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
"@
    systemctl enable --now unattended-upgrades
} elseif (Get-Command dnf -ErrorAction SilentlyContinue) {
    dnf install -y dnf-automatic
    # security-only, applied automatically
    sed -i 's/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf
    sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
    systemctl enable --now dnf-automatic.timer
}
'@
            Rollback = @'
if (Test-Path '/etc/apt/apt.conf.d/20auto-upgrades') {
    Set-Content -LiteralPath '/etc/apt/apt.conf.d/20auto-upgrades' -Value @"
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
"@
}
systemctl disable --now dnf-automatic.timer 2>$null
'@
        }
        [pscustomobject]@{
            Id = 'LNX-FW-ENABLE'; Tier = 1; Weight = 10; Category = 'Firewall'
            Title = 'Enable a default-deny host firewall'
            Rationale = 'Most distributions ship with no firewall rules at all, so every listening service is reachable from the local network. A default-deny inbound policy makes exposure deliberate rather than accidental.'
            Risk = 'Low, but SSH is explicitly allowed first. Applying a deny-all policy without that would lock you out of a remote machine.'
            Test = {
                $ufw = Invoke-NGCommand -FilePath 'ufw' -Arguments @('status')
                if ($ufw.found -and $ufw.ok) { return ($ufw.stdout -match 'Status:\s*active') }
                $fw = Invoke-NGCommand -FilePath 'firewall-cmd' -Arguments @('--state')
                if ($fw.found) { return ($fw.stdout.Trim() -eq 'running') }
                $ipt = Invoke-NGCommand -FilePath 'iptables' -Arguments @('-S')
                ($ipt.ok -and $ipt.stdout -match '(?m)^-P INPUT (DROP|REJECT)')
            }
            Apply = @'
if (Get-Command ufw -ErrorAction SilentlyContinue) {
    # Allow SSH BEFORE enabling, or this locks out a remote session.
    $sshPort = 22
    $sshd = & sshd -T 2>$null | Select-String -Pattern '^port\s+(\d+)'
    if ($sshd) { $sshPort = [int]$sshd.Matches[0].Groups[1].Value }
    ufw allow $sshPort/tcp comment 'SSH - allowed by NetGuard before default-deny'
    ufw default deny incoming
    ufw default allow outgoing
    ufw logging on
    ufw --force enable
} elseif (Get-Command firewall-cmd -ErrorAction SilentlyContinue) {
    systemctl enable --now firewalld
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --reload
} else {
    Write-Warning 'Neither ufw nor firewalld is installed. Install one: apt install ufw'
}
'@
            Rollback = @'
if (Get-Command ufw -ErrorAction SilentlyContinue) { ufw --force disable }
elseif (Get-Command firewall-cmd -ErrorAction SilentlyContinue) { systemctl disable --now firewalld }
'@
        }
        [pscustomobject]@{
            Id = 'LNX-FW-LOG'; Tier = 1; Weight = 6; Category = 'Firewall'
            Title = 'Enable firewall drop logging'
            Rationale = 'Without dropped-packet logs there is no record of anything probing this host, which is a blind spot exactly at the network edge.'
            Risk = 'None beyond log volume; journald rotates it.'
            Test = {
                $ufw = Invoke-NGCommand -FilePath 'ufw' -Arguments @('status', 'verbose')
                if ($ufw.ok) { return ($ufw.stdout -match '(?m)^Logging:\s*on') }
                $ipt = Invoke-NGCommand -FilePath 'iptables' -Arguments @('-S')
                ($ipt.ok -and $ipt.stdout -match '-j LOG')
            }
            Apply = "if (Get-Command ufw -ErrorAction SilentlyContinue) { ufw logging low }"
            Rollback = "if (Get-Command ufw -ErrorAction SilentlyContinue) { ufw logging off }"
        }
        [pscustomobject]@{
            Id = 'LNX-SSH-NOROOT'; Tier = 1; Weight = 11; Category = 'Remote Access'
            Title = 'Disable direct root login over SSH'
            Rationale = 'root is the one username every attacker knows exists, so it absorbs the overwhelming majority of SSH brute-force traffic. Forcing a named account plus sudo also restores an audit trail of who did what.'
            Risk = 'Low, but confirm you have a working sudo-capable account with a key BEFORE applying, or you lose remote access to the machine.'
            Applicable = {
                # Not a failure if this host runs no SSH daemon at all.
                $null -ne (Get-Command sshd -ErrorAction SilentlyContinue)
            }
            Test = {
                $t = Invoke-NGCommand -FilePath 'sshd' -Arguments @('-T')
                if (-not $t.ok) { throw 'sshd -T failed; cannot read effective config' }
                ($t.stdout.ToLower() -match '(?m)^permitrootlogin\s+(no|prohibit-password|forced-commands-only)')
            }
            Apply = @'
# Verify an escape route exists first. Locking root out of a machine whose only
# other account cannot sudo is a self-inflicted outage.
$sudoers = @()
foreach ($g in 'sudo','wheel','admin') {
    $line = (Select-String -Path '/etc/group' -Pattern "^${g}:" -ErrorAction SilentlyContinue).Line
    if ($line) { $sudoers += ($line -split ':')[3] -split ',' | Where-Object { $_ } }
}
if ($sudoers.Count -eq 0) {
    Write-Warning 'No user is in sudo/wheel/admin. Disabling root SSH would lock you out.'
    Write-Warning 'Create one first:  adduser <name> && usermod -aG sudo <name>'
    throw 'aborted: no sudo-capable account'
}
Write-Host "sudo-capable accounts found: $($sudoers -join ', ')"

$cfg = '/etc/ssh/sshd_config'
if (Select-String -Path $cfg -Pattern '^\s*PermitRootLogin' -Quiet) {
    sed -i 's/^\s*PermitRootLogin.*/PermitRootLogin no/' $cfg
} else {
    Add-Content -LiteralPath $cfg -Value 'PermitRootLogin no'
}
sshd -t
if ($LASTEXITCODE -eq 0) { systemctl reload sshd 2>$null; systemctl reload ssh 2>$null }
else { Write-Warning 'sshd config test FAILED - not reloading. Fix the config before restarting sshd.' }
'@
            Rollback = @'
sed -i 's/^\s*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sshd -t
if ($LASTEXITCODE -eq 0) { systemctl reload sshd 2>$null; systemctl reload ssh 2>$null }
'@
        }
        [pscustomobject]@{
            Id = 'LNX-SYSCTL-NET'; Tier = 1; Weight = 7; Category = 'Kernel'
            Title = 'Apply network-hardening sysctl settings'
            Rationale = 'Disables source routing, ICMP redirect acceptance and IP forwarding, and enables reverse-path filtering and SYN cookies. These block spoofing and redirect attacks that need no vulnerability to work.'
            Risk = 'Low on a workstation. Do NOT apply the ip_forward setting on a router, VPN gateway or Docker host - the script skips it when Docker is present.'
            Test = {
                $rp = Invoke-NGCommand -FilePath 'sysctl' -Arguments @('-n', 'net.ipv4.conf.all.rp_filter')
                $sc = Invoke-NGCommand -FilePath 'sysctl' -Arguments @('-n', 'net.ipv4.tcp_syncookies')
                $rd = Invoke-NGCommand -FilePath 'sysctl' -Arguments @('-n', 'net.ipv4.conf.all.accept_redirects')
                ($rp.stdout.Trim() -eq '1') -and ($sc.stdout.Trim() -eq '1') -and ($rd.stdout.Trim() -eq '0')
            }
            Apply = @'
$conf = @"
# Written by NetGuard hardening (Tier 1)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
"@
# Forwarding is left alone when Docker/libvirt/k8s is present - they need it,
# and turning it off silently breaks every container's networking.
if (-not (Get-Command docker -ErrorAction SilentlyContinue) -and
    -not (Test-Path '/var/lib/libvirt') -and -not (Test-Path '/etc/kubernetes')) {
    $conf += "`nnet.ipv4.ip_forward = 0`nnet.ipv6.conf.all.forwarding = 0"
} else {
    Write-Host 'Container/virtualisation runtime detected - leaving ip_forward unchanged.'
}
Set-Content -LiteralPath '/etc/sysctl.d/99-netguard-net.conf' -Value $conf
sysctl --system | Out-Null
'@
            Rollback = "Remove-Item '/etc/sysctl.d/99-netguard-net.conf' -Force -ErrorAction SilentlyContinue`nsysctl --system | Out-Null"
        }
        [pscustomobject]@{
            Id = 'LNX-SYSCTL-KERNEL'; Tier = 1; Weight = 8; Category = 'Kernel'
            Title = 'Apply kernel-hardening sysctl settings'
            Rationale = 'ASLR, kernel pointer hiding, restricted dmesg, hardlink/symlink protection and ptrace_scope. Together these remove the information leaks and primitives that turn a memory-safety bug into a working local exploit.'
            Risk = 'Low. ptrace_scope=1 can break debuggers and some crash handlers; set it to 0 temporarily if you need gdb to attach to a running process.'
            Test = {
                $aslr = Invoke-NGCommand -FilePath 'sysctl' -Arguments @('-n', 'kernel.randomize_va_space')
                $kptr = Invoke-NGCommand -FilePath 'sysctl' -Arguments @('-n', 'kernel.kptr_restrict')
                $link = Invoke-NGCommand -FilePath 'sysctl' -Arguments @('-n', 'fs.protected_symlinks')
                ($aslr.stdout.Trim() -eq '2') -and ($kptr.stdout.Trim() -in '1', '2') -and ($link.stdout.Trim() -eq '1')
            }
            Apply = @'
Set-Content -LiteralPath '/etc/sysctl.d/99-netguard-kernel.conf' -Value @"
# Written by NetGuard hardening (Tier 1)
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
"@
sysctl --system | Out-Null
'@
            Rollback = "Remove-Item '/etc/sysctl.d/99-netguard-kernel.conf' -Force -ErrorAction SilentlyContinue`nsysctl --system | Out-Null"
        }
        [pscustomobject]@{
            Id = 'LNX-JOURNAL'; Tier = 1; Weight = 6; Category = 'Logging'
            Title = 'Make the systemd journal persistent'
            Rationale = 'By default many distributions keep the journal in memory only, so every log is destroyed on reboot - including the reboot an attacker triggers. Persistent storage is what makes after-the-fact investigation possible at all.'
            Risk = 'None beyond disk usage, which is capped at 500 MB here.'
            Test = { (Test-Path '/var/log/journal') -and ((Get-NGFileTextSafe '/etc/systemd/journald.conf') -match '(?m)^\s*Storage\s*=\s*persistent') }
            Apply = @'
New-Item -ItemType Directory -Path '/var/log/journal' -Force | Out-Null
systemd-tmpfiles --create --prefix /var/log/journal
$conf = Get-Content '/etc/systemd/journald.conf' -Raw
if ($conf -match '(?m)^\s*#?\s*Storage\s*=') {
    $conf = $conf -replace '(?m)^\s*#?\s*Storage\s*=.*', 'Storage=persistent'
} else { $conf += "`nStorage=persistent" }
if ($conf -match '(?m)^\s*#?\s*SystemMaxUse\s*=') {
    $conf = $conf -replace '(?m)^\s*#?\s*SystemMaxUse\s*=.*', 'SystemMaxUse=500M'
} else { $conf += "`nSystemMaxUse=500M" }
Set-Content -LiteralPath '/etc/systemd/journald.conf' -Value $conf
systemctl restart systemd-journald
'@
            Rollback = @'
$conf = Get-Content '/etc/systemd/journald.conf' -Raw
$conf = $conf -replace '(?m)^Storage=persistent', '#Storage=auto'
Set-Content -LiteralPath '/etc/systemd/journald.conf' -Value $conf
systemctl restart systemd-journald
'@
        }
        [pscustomobject]@{
            Id = 'LNX-COREDUMP'; Tier = 1; Weight = 4; Category = 'Kernel'
            Title = 'Disable core dumps'
            Rationale = 'A core dump of a crashed privileged process can contain keys, passwords and session tokens, and it lands in a world-readable location by default.'
            Risk = 'Low. Only matters if you are actively debugging crashes.'
            Test = {
                $limits = Get-NGFileTextSafe '/etc/security/limits.d/99-netguard.conf'
                $sysctl = Invoke-NGCommand -FilePath 'sysctl' -Arguments @('-n', 'fs.suid_dumpable')
                ($null -ne $limits -and $limits -match 'hard core 0') -and ($sysctl.stdout.Trim() -eq '0')
            }
            Apply = @'
Set-Content -LiteralPath '/etc/security/limits.d/99-netguard.conf' -Value @"
* hard core 0
* soft core 0
"@
Set-Content -LiteralPath '/etc/sysctl.d/99-netguard-coredump.conf' -Value 'fs.suid_dumpable = 0'
sysctl --system | Out-Null
if (Test-Path '/etc/systemd/coredump.conf') {
    sed -i 's/^#\?Storage=.*/Storage=none/' /etc/systemd/coredump.conf
}
'@
            Rollback = @'
Remove-Item '/etc/security/limits.d/99-netguard.conf' -Force -ErrorAction SilentlyContinue
Remove-Item '/etc/sysctl.d/99-netguard-coredump.conf' -Force -ErrorAction SilentlyContinue
sysctl --system | Out-Null
'@
        }
        [pscustomobject]@{
            Id = 'LNX-AUDITD'; Tier = 1; Weight = 9; Category = 'Logging'
            Title = 'Install auditd with execve and identity rules'
            Rationale = 'auditd is the Linux equivalent of command-line process auditing. Without it NetGuard can see that a process ran but not what it was told to do, and cannot detect changes to passwd, shadow, sudoers or the audit rules themselves.'
            Risk = 'Low. Some log volume. The rules here deliberately exclude high-frequency syscalls to avoid drowning the disk.'
            Test = {
                $r = Invoke-NGCommand -FilePath 'auditctl' -Arguments @('-l')
                $r.found -and $r.ok -and ($r.stdout -match 'execve')
            }
            Apply = @'
if (Get-Command apt-get -ErrorAction SilentlyContinue) { apt-get install -y auditd audispd-plugins }
elseif (Get-Command dnf -ErrorAction SilentlyContinue) { dnf install -y audit }

Set-Content -LiteralPath '/etc/audit/rules.d/netguard.rules' -Value @"
## NetGuard audit rules
-D
-b 8192
--backlog_wait_time 60000

## Identity and privilege files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege

## Command execution by real users (uid>=1000). System daemons are excluded or
## the log fills with routine activity and the useful records scroll away.
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k exec
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k exec

## Privilege escalation and module loading
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=4294967295 -k privesc
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

## Persistence locations
-w /etc/ld.so.preload -p wa -k preload
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd

## Make the rules themselves immutable until reboot. MUST be last.
-e 2
"@
systemctl enable --now auditd
augenrules --load 2>$null
Write-Host 'Audit rules are immutable (-e 2) until the next reboot, which is what stops an attacker quietly unloading them.'
'@
            Rollback = @'
Remove-Item '/etc/audit/rules.d/netguard.rules' -Force -ErrorAction SilentlyContinue
augenrules --load 2>$null
Write-Host 'Rules removed. A REBOOT is required because -e 2 made the running rules immutable.'
'@
        }
        [pscustomobject]@{
            Id = 'LNX-UMASK'; Tier = 1; Weight = 5; Category = 'Filesystem'
            Title = 'Set a restrictive default umask (027)'
            Rationale = 'The common default of 022 makes every new file world-readable. On a multi-user machine that silently exposes logs, configs and keys to every local account.'
            Risk = 'Low. Occasionally a service expects world-readable files and needs an explicit chmod.'
            Test = {
                $ld = Get-NGFileTextSafe '/etc/login.defs'
                ($null -ne $ld) -and ($ld -match '(?m)^UMASK\s+027')
            }
            Apply = @'
if (Select-String -Path '/etc/login.defs' -Pattern '^UMASK' -Quiet) {
    sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
} else {
    Add-Content -LiteralPath '/etc/login.defs' -Value 'UMASK 027'
}
Set-Content -LiteralPath '/etc/profile.d/99-netguard-umask.sh' -Value 'umask 027'
'@
            Rollback = @'
sed -i 's/^UMASK.*/UMASK 022/' /etc/login.defs
Remove-Item '/etc/profile.d/99-netguard-umask.sh' -Force -ErrorAction SilentlyContinue
'@
        }

        # ----------------------------------------------------------- TIER 2 ----
        [pscustomobject]@{
            Id = 'LNX-SSH-NOPASS'; Tier = 2; Weight = 11; Category = 'Remote Access'
            Title = 'Disable SSH password authentication (keys only)'
            Rationale = 'Password authentication is what makes SSH brute-forcing viable. With keys only, an attacker with the correct password still cannot log in, and credential-stuffing from other breaches stops mattering.'
            Risk = 'MODERATE. You will be locked out if you have not installed a working public key. The script refuses to apply unless it finds one.'
            Applicable = {
                # Not a failure if this host runs no SSH daemon at all.
                $null -ne (Get-Command sshd -ErrorAction SilentlyContinue)
            }
            Test = {
                $t = Invoke-NGCommand -FilePath 'sshd' -Arguments @('-T')
                if (-not $t.ok) { throw 'sshd -T failed; cannot read effective config' }
                ($t.stdout.ToLower() -match '(?m)^passwordauthentication\s+no')
            }
            Apply = @'
# Refuse to proceed without a key on disk. This check is the difference between
# a hardening step and an outage.
$keyFound = $false
foreach ($ak in (Get-ChildItem '/home/*/.ssh/authorized_keys','/root/.ssh/authorized_keys' -ErrorAction SilentlyContinue)) {
    $content = Get-Content $ak.FullName -ErrorAction SilentlyContinue
    if ($content -and ($content | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') })) {
        $keyFound = $true
        Write-Host "  key found: $($ak.FullName)"
    }
}
if (-not $keyFound) {
    Write-Warning 'No authorized_keys entries found anywhere. Disabling password auth WILL lock you out.'
    Write-Warning 'From your client first:  ssh-copy-id user@thishost'
    throw 'aborted: no SSH public key installed'
}

$cfg = '/etc/ssh/sshd_config'
foreach ($pair in @(
    @('PasswordAuthentication','no'),
    @('ChallengeResponseAuthentication','no'),
    @('KbdInteractiveAuthentication','no'),
    @('PermitEmptyPasswords','no'),
    @('MaxAuthTries','3'),
    @('LoginGraceTime','30'),
    @('X11Forwarding','no'))) {
    $k = $pair[0]; $v = $pair[1]
    if (Select-String -Path $cfg -Pattern "^\s*#?\s*$k\b" -Quiet) {
        sed -i "s/^\s*#\?\s*$k.*/$k $v/" $cfg
    } else {
        Add-Content -LiteralPath $cfg -Value "$k $v"
    }
}
sshd -t
if ($LASTEXITCODE -eq 0) {
    systemctl reload sshd 2>$null; systemctl reload ssh 2>$null
    Write-Host 'Password auth disabled. KEEP YOUR CURRENT SESSION OPEN and verify a new key login works before closing it.' -ForegroundColor Yellow
} else { Write-Warning 'sshd config test FAILED - not reloading.' }
'@
            Rollback = @'
sed -i 's/^\s*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sshd -t
if ($LASTEXITCODE -eq 0) { systemctl reload sshd 2>$null; systemctl reload ssh 2>$null }
'@
        }
        [pscustomobject]@{
            Id = 'LNX-NOSUDO-NOPASS'; Tier = 2; Weight = 8; Category = 'Privilege'
            Title = 'Remove NOPASSWD entries from sudoers'
            Rationale = 'A NOPASSWD rule means any process running as that user - including malware that never knew the password - can become root silently. It converts a browser exploit into a full compromise.'
            Risk = 'Moderate. Breaks automation that relies on passwordless sudo. Review each rule before applying; CI runners and Ansible often need one.'
            Test = {
                $found = $false
                foreach ($file in @('/etc/sudoers') + @(Get-ChildItem '/etc/sudoers.d' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })) {
                    $txt = Get-NGFileTextSafe $file
                    if (-not $txt) { continue }
                    foreach ($line in ($txt -split "`n")) {
                        $t = $line.Trim()
                        if ($t -and -not $t.StartsWith('#') -and $t -match 'NOPASSWD') { $found = $true }
                    }
                }
                -not $found
            }
            Apply = @'
# Comment out rather than delete, so the original intent is recoverable.
foreach ($file in @('/etc/sudoers') + @(Get-ChildItem '/etc/sudoers.d' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })) {
    $lines = Get-Content $file -ErrorAction SilentlyContinue
    if (-not $lines) { continue }
    $changed = $false
    $out = foreach ($line in $lines) {
        if ($line.Trim() -and -not $line.Trim().StartsWith('#') -and $line -match 'NOPASSWD') {
            $changed = $true
            Write-Host "  commenting out in ${file}: $line"
            "# NetGuard disabled NOPASSWD: $line"
        } else { $line }
    }
    if ($changed) {
        $tmp = "$file.netguard.tmp"
        Set-Content -LiteralPath $tmp -Value $out
        # visudo -c validates BEFORE replacing; a malformed sudoers file can make
        # sudo refuse to run at all, which is unrecoverable without a root shell.
        & visudo -c -f $tmp
        if ($LASTEXITCODE -eq 0) { Move-Item $tmp $file -Force; chmod 440 $file }
        else { Write-Warning "validation failed for $file - left unchanged"; Remove-Item $tmp -Force }
    }
}
'@
            Rollback = @'
foreach ($file in @('/etc/sudoers') + @(Get-ChildItem '/etc/sudoers.d' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })) {
    $lines = Get-Content $file -ErrorAction SilentlyContinue
    if (-not $lines) { continue }
    $out = $lines -replace '^# NetGuard disabled NOPASSWD: ', ''
    $tmp = "$file.netguard.tmp"
    Set-Content -LiteralPath $tmp -Value $out
    & visudo -c -f $tmp
    if ($LASTEXITCODE -eq 0) { Move-Item $tmp $file -Force; chmod 440 $file }
    else { Remove-Item $tmp -Force }
}
'@
        }
        [pscustomobject]@{
            Id = 'LNX-CLAMAV'; Tier = 2; Weight = 7; Category = 'Antivirus'
            Title = 'Install ClamAV with on-access scanning'
            Rationale = 'Most Linux desktops run no malware scanner at all, which leaves the NetGuard download pipeline with no signature stage. ClamAV also catches Windows malware being stored or forwarded from this host.'
            Risk = 'Moderate. clamonacc adds measurable I/O overhead, and freshclam needs outbound HTTPS. On a low-RAM machine the daemon alone uses roughly 1 GB.'
            Test = {
                $r = Invoke-NGCommand -FilePath 'systemctl' -Arguments @('is-active', 'clamav-daemon')
                ($r.stdout.Trim() -eq 'active')
            }
            Apply = @'
if (Get-Command apt-get -ErrorAction SilentlyContinue) { apt-get install -y clamav clamav-daemon }
elseif (Get-Command dnf -ErrorAction SilentlyContinue) { dnf install -y clamav clamd clamav-update }
systemctl stop clamav-freshclam 2>$null
freshclam
systemctl enable --now clamav-freshclam
systemctl enable --now clamav-daemon
Write-Host 'ClamAV installed. On-access scanning (clamav-clamonacc) is NOT enabled by default'
Write-Host 'because of its I/O cost. Enable it with: systemctl enable --now clamav-clamonacc'
'@
            Rollback = @'
systemctl disable --now clamav-clamonacc 2>$null
systemctl disable --now clamav-daemon 2>$null
systemctl disable --now clamav-freshclam 2>$null
'@
        }
        [pscustomobject]@{
            Id = 'LNX-MOUNT-HARDEN'; Tier = 2; Weight = 7; Category = 'Filesystem'
            Title = 'Mount /tmp and /dev/shm with noexec, nosuid, nodev'
            Rationale = 'World-writable directories are where dropped payloads land. noexec removes the ability to execute them from there at all, which breaks a large fraction of commodity Linux malware and exploit chains.'
            Risk = 'Moderate. Some installers, package build systems and older Java versions execute from /tmp and will fail. Test before making it permanent.'
            Test = {
                $m = Invoke-NGCommand -FilePath 'findmnt' -Arguments @('-n', '-o', 'OPTIONS', '/dev/shm')
                ($m.ok -and $m.stdout -match 'noexec' -and $m.stdout -match 'nosuid')
            }
            Apply = @'
# /dev/shm first - it is safe almost everywhere.
if (-not (Select-String -Path '/etc/fstab' -Pattern '/dev/shm' -Quiet)) {
    Add-Content -LiteralPath '/etc/fstab' -Value 'tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0'
}
mount -o remount,noexec,nosuid,nodev /dev/shm
Write-Host '/dev/shm remounted with noexec,nosuid,nodev'

# /tmp is riskier. Only touch it when it is already a separate mount; converting
# a directory into a tmpfs can hide files that services expect to persist.
$tmpMount = & findmnt -n -o SOURCE /tmp 2>$null
if ($tmpMount) {
    Write-Host 'Remounting /tmp with noexec,nosuid,nodev'
    mount -o remount,noexec,nosuid,nodev /tmp
    Write-Host 'Test your package manager and installers. To persist, add the options to /etc/fstab.'
} else {
    Write-Host '/tmp is not a separate mount - skipped. Enable it deliberately with:'
    Write-Host '  systemctl enable --now tmp.mount'
}
'@
            Rollback = @'
mount -o remount,exec /dev/shm 2>$null
mount -o remount,exec /tmp 2>$null
sed -i '/tmpfs \/dev\/shm tmpfs defaults,noexec,nosuid,nodev/d' /etc/fstab
'@
        }
        [pscustomobject]@{
            Id = 'LNX-FAIL2BAN'; Tier = 2; Weight = 6; Category = 'Remote Access'
            Title = 'Install fail2ban for SSH'
            Rationale = 'Automatically bans source addresses after repeated authentication failures. It does not replace key-only authentication, but it removes the constant background noise and the log volume that hides a real attempt.'
            Risk = 'Moderate. A fat-fingered password from your own address can ban you. The default here whitelists private ranges.'
            Test = {
                $r = Invoke-NGCommand -FilePath 'systemctl' -Arguments @('is-active', 'fail2ban')
                ($r.stdout.Trim() -eq 'active')
            }
            Apply = @'
if (Get-Command apt-get -ErrorAction SilentlyContinue) { apt-get install -y fail2ban }
elseif (Get-Command dnf -ErrorAction SilentlyContinue) { dnf install -y fail2ban }
Set-Content -LiteralPath '/etc/fail2ban/jail.d/netguard.conf' -Value @"
[DEFAULT]
# Never ban yourself off your own LAN.
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
"@
systemctl enable --now fail2ban
'@
            Rollback = @'
Remove-Item '/etc/fail2ban/jail.d/netguard.conf' -Force -ErrorAction SilentlyContinue
systemctl disable --now fail2ban 2>$null
'@
        }

        # ----------------------------------------------------------- TIER 3 ----
        [pscustomobject]@{
            Id = 'LNX-APPARMOR'; Tier = 3; Weight = 9; Category = 'Mandatory Access Control'
            Title = 'Enable AppArmor or SELinux in enforcing mode'
            Rationale = 'Mandatory access control confines a compromised service to what it legitimately needs. It is the difference between a web server exploit that reads web files and one that reads /etc/shadow.'
            Risk = 'HIGH if profiles are untuned. Applied in complain/permissive mode first so you can find what would break before anything actually does.'
            Test = {
                $aa = Invoke-NGCommand -FilePath 'aa-status' -Arguments @('--enabled')
                if ($aa.found -and $aa.ok) {
                    $prof = Invoke-NGCommand -FilePath 'aa-status'
                    return ($prof.ok -and $prof.stdout -match 'profiles are in enforce mode')
                }
                $se = Invoke-NGCommand -FilePath 'getenforce'
                ($se.found -and $se.stdout.Trim() -eq 'Enforcing')
            }
            Apply = @'
if (Get-Command aa-status -ErrorAction SilentlyContinue) {
    apt-get install -y apparmor apparmor-utils apparmor-profiles 2>$null
    systemctl enable --now apparmor
    # COMPLAIN mode logs violations without blocking. Review for a week, then
    # promote with aa-enforce. Enforcing untuned profiles breaks services.
    foreach ($p in (Get-ChildItem '/etc/apparmor.d' -File -ErrorAction SilentlyContinue)) {
        & aa-complain $p.FullName 2>$null
    }
    Write-Host 'AppArmor profiles set to COMPLAIN mode. Review violations with: journalctl -k | grep apparmor'
    Write-Host 'Promote a clean profile with: aa-enforce /etc/apparmor.d/<profile>'
} elseif (Get-Command getenforce -ErrorAction SilentlyContinue) {
    sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
    setenforce 0
    Write-Host 'SELinux set to PERMISSIVE. Review denials with: ausearch -m AVC -ts recent'
    Write-Host 'Switch to enforcing in /etc/selinux/config once clean, then reboot.'
} else {
    Write-Warning 'Neither AppArmor nor SELinux is available on this system.'
}
'@
            Rollback = @'
if (Get-Command aa-status -ErrorAction SilentlyContinue) { systemctl disable --now apparmor }
elseif (Get-Command getenforce -ErrorAction SilentlyContinue) {
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    setenforce 0 2>$null
}
'@
        }
        [pscustomobject]@{
            Id = 'LNX-USBGUARD'; Tier = 3; Weight = 6; Category = 'Device Control'
            Title = 'Install USBGuard with the current devices allowlisted'
            Rationale = 'Blocks unknown USB devices from attaching, which stops BadUSB-style keystroke injection from an unattended machine.'
            Risk = 'HIGH if misconfigured - it can block your own keyboard. The script generates a policy from currently-attached devices first, so what is plugged in now keeps working.'
            Test = {
                $r = Invoke-NGCommand -FilePath 'systemctl' -Arguments @('is-active', 'usbguard')
                ($r.stdout.Trim() -eq 'active')
            }
            Apply = @'
if (Get-Command apt-get -ErrorAction SilentlyContinue) { apt-get install -y usbguard }
elseif (Get-Command dnf -ErrorAction SilentlyContinue) { dnf install -y usbguard }
# Generate the policy from what is attached RIGHT NOW, so the keyboard and mouse
# you are using survive the change.
Write-Host 'Generating allowlist from currently attached USB devices...'
& usbguard generate-policy > /etc/usbguard/rules.conf
chmod 600 /etc/usbguard/rules.conf
systemctl enable --now usbguard
Write-Host 'USBGuard active. New devices are BLOCKED until allowed with: usbguard allow-device <id>'
Write-Host 'List pending devices with: usbguard list-devices'
'@
            Rollback = 'systemctl disable --now usbguard 2>$null'
        }
        [pscustomobject]@{
            Id = 'LNX-MODULES'; Tier = 3; Weight = 7; Category = 'Kernel'
            Title = 'Blacklist uncommon filesystem and network modules'
            Rationale = 'Rarely-used kernel modules (cramfs, jffs2, dccp, sctp, rds, tipc) have a long history of memory-safety bugs and are auto-loaded on demand, so an unprivileged process can reach that attack surface simply by asking for it.'
            Risk = 'Moderate. If you genuinely use one of these filesystems or protocols it will stop working. Check before applying.'
            Test = {
                $conf = Get-NGFileTextSafe '/etc/modprobe.d/netguard-blacklist.conf'
                ($null -ne $conf) -and ($conf -match 'install dccp /bin/true')
            }
            Apply = @'
Set-Content -LiteralPath '/etc/modprobe.d/netguard-blacklist.conf' -Value @"
# Written by NetGuard hardening (Tier 3)
# Uncommon filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
# Uncommon network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
# Legacy / rarely needed
install firewire-core /bin/true
install thunderbolt /bin/true
"@
Write-Host 'Module blacklist written. NOTE: squashfs is required by snap packages -'
Write-Host 'remove that line if you use snaps. Takes effect on next module load or reboot.'
'@
            Rollback = "Remove-Item '/etc/modprobe.d/netguard-blacklist.conf' -Force -ErrorAction SilentlyContinue"
        }
    )
}

# ============================================== LINUX-SPECIFIC DETECTIONS ====

function Find-NGPlatformPostureFindings {
    <#
        Linux detections the cross-platform rules cannot express. The shared
        engine already handles antivirus health, firewall state, disk encryption,
        patching, logging and uptime.

        Tri-state discipline applies: test -eq $false, never -not $x.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Posture)
    $f = New-Object System.Collections.Generic.List[psobject]
    $agentId = 'posture-linux'
    $raw = $Posture.raw

    # ---------------- SSH exposure
    $ssh = $Posture.remoteAccess.ssh
    if ($ssh -and $ssh.enabled -eq $true) {
        if ($ssh.rootLogin -eq 'yes') {
            $f.Add((New-NGFinding -Category 'Exposure' -Severity 'High' -Agent $agentId `
                        -Title 'SSH permits direct root login with a password' `
                        -Detail 'root is the one username every attacker knows exists, so it absorbs the majority of SSH brute-force traffic. Direct root login also destroys the audit trail of who actually did what.' `
                        -Recommendation 'Set PermitRootLogin no in /etc/ssh/sshd_config and use a named account with sudo. Confirm you have a sudo-capable account first.' `
                        -Evidence $ssh -FingerprintSeed 'ssh-root-login'))
        }
        if ($ssh.passwordAuth -eq $true) {
            $f.Add((New-NGFinding -Category 'Exposure' -Severity 'Medium' -Agent $agentId `
                        -Title 'SSH accepts password authentication' `
                        -Detail 'Password authentication is what makes SSH brute-forcing and credential stuffing viable. With keys only, knowing the password is not enough to log in.' `
                        -Recommendation 'Install your public key (ssh-copy-id), verify it works, then set PasswordAuthentication no. The Tier 2 script checks for a key before applying.' `
                        -Evidence $ssh -FingerprintSeed 'ssh-password-auth'))
        }
        if ($raw.sshdEffective -and $raw.sshdEffective.permitEmptyPasswords) {
            $f.Add((New-NGFinding -Category 'Exposure' -Severity 'Critical' -Agent $agentId `
                        -Title 'SSH permits empty passwords' `
                        -Detail 'Any account with a blank password can be logged into remotely with no credential at all.' `
                        -Recommendation 'Set PermitEmptyPasswords no immediately and audit every account for empty password hashes.' `
                        -Evidence $raw.sshdEffective -FingerprintSeed 'ssh-empty-passwords'))
        }
    }

    # ---------------- passwordless sudo
    $noPasswd = @($raw.sudoNoPasswd)
    if ((Get-NGCount $noPasswd) -gt 0) {
        $f.Add((New-NGFinding -Category 'Privilege' -Severity 'High' -Agent $agentId `
                    -Title "$(Get-NGCount $noPasswd) passwordless sudo rule(s) configured" `
                    -Detail ("A NOPASSWD rule means any process running as that user - including malware that never knew the password - can become root silently. It converts a browser exploit into a full compromise.`n`n" +
                             (($noPasswd | ForEach-Object { "- $($_.file): $($_.rule)" }) -join "`n")) `
                    -Recommendation 'Remove rules you do not need. If automation requires one, scope it to a single exact command rather than ALL.' `
                    -Evidence $noPasswd -FingerprintSeed 'sudo-nopasswd'))
    }

    # ---------------- mandatory access control
    $mac = $raw.mandatoryAccessControl
    if ($mac) {
        $aaOff = ($mac.apparmorEnabled -eq $false)
        $seOff = ($mac.selinuxMode -in 'Disabled', 'Permissive')
        $neither = ($null -eq $mac.apparmorEnabled -and $null -eq $mac.selinuxMode)
        if ($aaOff -or $seOff -or $neither) {
            $state = if ($mac.selinuxMode) { "SELinux: $($mac.selinuxMode)" }
                     elseif ($null -ne $mac.apparmorEnabled) { "AppArmor enabled: $($mac.apparmorEnabled)" }
                     else { 'neither AppArmor nor SELinux detected' }
            $f.Add((New-NGFinding -Category 'Hardening' -Severity 'Medium' -Agent $agentId `
                        -Title 'Mandatory access control is not enforcing' `
                        -Detail "Current state: $state`n`nMandatory access control confines a compromised service to what it legitimately needs. It is the difference between a web server exploit that reads web files and one that reads /etc/shadow." `
                        -Recommendation 'Enable AppArmor or SELinux. The Tier 3 script applies it in complain/permissive mode first so you can find what would break before anything does.' `
                        -Evidence $mac -FingerprintSeed 'mac-not-enforcing'))
        }
    }

    # ---------------- kernel hardening sysctls
    $sc = $raw.sysctl
    if ($sc) {
        if ($sc['kernel.randomize_va_space'] -and $sc['kernel.randomize_va_space'] -ne '2') {
            $f.Add((New-NGFinding -Category 'Kernel' -Severity 'High' -Agent $agentId `
                        -Title 'Full ASLR is not enabled' `
                        -Detail "kernel.randomize_va_space = $($sc['kernel.randomize_va_space']) (should be 2). Without full address space randomisation, memory-corruption bugs become far easier to exploit reliably." `
                        -Recommendation 'Set kernel.randomize_va_space = 2 in /etc/sysctl.d/. The Tier 1 script does this.' `
                        -Evidence $sc -FingerprintSeed 'aslr-weak'))
        }
        if ($sc['kernel.kptr_restrict'] -eq '0') {
            $f.Add((New-NGFinding -Category 'Kernel' -Severity 'Medium' -Agent $agentId `
                        -Title 'Kernel pointers are exposed to unprivileged users' `
                        -Detail 'kptr_restrict = 0 leaks kernel addresses through /proc, which defeats KASLR and is the first step in most local privilege escalation chains.' `
                        -Recommendation 'Set kernel.kptr_restrict = 2.' `
                        -Evidence $sc -FingerprintSeed 'kptr-exposed'))
        }
        if ($sc['net.ipv4.conf.all.accept_redirects'] -eq '1') {
            $f.Add((New-NGFinding -Category 'Kernel' -Severity 'Medium' -Agent $agentId `
                        -Title 'ICMP redirects are accepted' `
                        -Detail 'Accepting ICMP redirects lets anything on the local network reroute this host traffic through itself - a man-in-the-middle with no vulnerability required.' `
                        -Recommendation 'Set net.ipv4.conf.all.accept_redirects = 0.' `
                        -Evidence $sc -FingerprintSeed 'icmp-redirects'))
        }
        if ($sc['fs.protected_symlinks'] -eq '0' -or $sc['fs.protected_hardlinks'] -eq '0') {
            $f.Add((New-NGFinding -Category 'Kernel' -Severity 'Medium' -Agent $agentId `
                        -Title 'Symlink/hardlink protection is disabled' `
                        -Detail 'Without these, a classic symlink race in any privileged process that writes to a world-writable directory becomes exploitable.' `
                        -Recommendation 'Set fs.protected_symlinks = 1 and fs.protected_hardlinks = 1.' `
                        -Evidence $sc -FingerprintSeed 'link-protection-off'))
        }
    }

    # ---------------- journal persistence
    if ($raw.journalPersistent -eq $false) {
        $f.Add((New-NGFinding -Category 'Logging' -Severity 'High' -Agent $agentId `
                    -Title 'System journal is volatile - logs are lost on reboot' `
                    -Detail 'The journal is stored in memory only, so every log is destroyed on reboot, including the reboot an attacker triggers to clean up. After-the-fact investigation becomes impossible.' `
                    -Recommendation 'Set Storage=persistent in /etc/systemd/journald.conf and create /var/log/journal. The Tier 1 script does this.' `
                    -Evidence @{ persistent = $false } -FingerprintSeed 'journal-volatile'))
    }

    # ---------------- NFS exports
    foreach ($share in @($Posture.shares)) {
        if ($share.name -eq 'nfs' -and $share.description -match '\*|0\.0\.0\.0/0') {
            $f.Add((New-NGFinding -Category 'Exposure' -Severity 'High' -Agent $agentId `
                        -Title "NFS export is world-readable: $($share.path)" `
                        -Detail "Export line: $($share.description)`n`nAn export with a wildcard host is available to any machine that can reach this one." `
                        -Recommendation 'Restrict the export to specific hosts or subnets, and add root_squash.' `
                        -Evidence $share -FingerprintSeed "nfs-wildcard|$($share.path)"))
        }
    }

    , @($f)
}

Export-ModuleMember -Function *
