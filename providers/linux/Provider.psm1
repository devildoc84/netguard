<#
    NetGuard Linux provider.

    Implements the contract in lib/NetGuard.Platform.psm1 for systemd-based
    distributions (Debian/Ubuntu, RHEL/Fedora, Arch, SUSE). Requires PowerShell 7.

    DESIGN NOTES

    Shelling out is the right call here. Linux exposes its state through
    well-defined command output (ss, systemctl, journalctl, ip) rather than
    through an object API, and parsing those is more portable across distros
    than reading /proc and /sys layouts that differ between kernels. Every
    invocation goes through Invoke-NGCommand, which never throws and reports
    "command missing" distinctly from "command returned nothing" - the
    difference between "cannot check" and "nothing found", which must never be
    conflated in a monitoring tool.

    Root is needed for the same things elevation is needed for on Windows:
    auditd config, shadow file, some journal units, iptables. Everything
    degrades to $null (unknown) rather than to a reassuring default.
#>

# Dependencies are loaded by Import-NGStack (lib/NetGuard.Platform.psm1),
# in order, exactly once. This module deliberately does NOT import its
# siblings: an Import-Module -Force from inside a module unloads and
# reloads the shared module graph mid-import, discarding module-scoped
# state and breaking command resolution in ways that only show up at
# runtime. Load order belongs to one place, not nine.
# ------------------------------------------------------------- helpers -------

function Invoke-NGCommand {
    <#
        Runs an external command and returns a structured result.

        Never throws. Distinguishes three outcomes that matter:
          found = $false   the binary is not installed -> "cannot check"
          ok    = $false   it ran and failed           -> "check failed"
          ok    = $true    it ran                      -> trust stdout
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 20
    )
    $exe = (Get-Command $FilePath -ErrorAction SilentlyContinue)
    if (-not $exe) {
        return [pscustomobject]@{ found = $false; ok = $false; exitCode = -1; stdout = ''; stderr = "not installed: $FilePath" }
    }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exe.Source
        foreach ($a in $Arguments) { [void]$psi.ArgumentList.Add($a) }
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true

        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        [void]$p.Start()
        # Start async reads BEFORE waiting, or a chatty child fills the pipe
        # buffer and both sides block forever.
        $so = $p.StandardOutput.ReadToEndAsync()
        $se = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
            try { $p.Kill() } catch { }
            return [pscustomobject]@{ found = $true; ok = $false; exitCode = -2; stdout = ''; stderr = 'timed out' }
        }
        [pscustomobject]@{
            found = $true; ok = ($p.ExitCode -eq 0); exitCode = $p.ExitCode
            stdout = $so.Result; stderr = $se.Result
        }
    }
    catch {
        [pscustomobject]@{ found = $true; ok = $false; exitCode = -3; stdout = ''; stderr = $_.Exception.Message }
    }
}

function Get-NGFileTextSafe {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch { $null }
}

function Test-NGElevated {
    # id -u is more reliable than $env:USER, which is unset under systemd.
    $r = Invoke-NGCommand -FilePath 'id' -Arguments @('-u')
    if ($r.ok) { return ($r.stdout.Trim() -eq '0') }
    $false
}

function Get-NGProviderInfo {
    $osRelease = Get-NGFileTextSafe '/etc/os-release'
    $name = 'Linux'
    $version = ''
    if ($osRelease) {
        if ($osRelease -match '(?m)^PRETTY_NAME="?([^"\r\n]+)"?') { $name = $Matches[1] }
        if ($osRelease -match '(?m)^VERSION_ID="?([^"\r\n]+)"?') { $version = $Matches[1] }
    }
    $kernel = (Invoke-NGCommand -FilePath 'uname' -Arguments @('-r')).stdout.Trim()
    [pscustomobject]@{
        name         = 'linux'
        displayName  = $name
        osVersion    = "$name (kernel $kernel)"
        psVersion    = $PSVersionTable.PSVersion.ToString()
        capabilities = @('systemd', 'journald', 'ss', 'iptables-or-nft', 'clamav-optional',
                         'auditd-optional', 'apparmor-or-selinux', 'luks')
    }
}

# ============================================================== SECRETS ======
<#
    AES-256-CBC with an HMAC-SHA256 tag, encrypt-then-MAC.

    Linux has no DPAPI. libsecret would need a desktop session and an unlocked
    keyring, which a systemd service running as root does not have - so the
    scheme is deliberately file-based: the key comes from the entropy file that
    Protect-NGFilePath restricts to 0600 root:root. As on Windows, the FILE
    PERMISSIONS are the real control; the cipher only protects the blob at rest
    if someone copies it off the machine without the key.

    Format: [16-byte IV][32-byte HMAC tag][ciphertext]
#>

function Get-NGDerivedKeys {
    param([byte[]]$Entropy)
    # Two independent keys from one secret, so the MAC key is never the cipher key.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $encKey = $sha.ComputeHash($Entropy + [Text.Encoding]::UTF8.GetBytes('netguard-enc-v1'))
    $macKey = $sha.ComputeHash($Entropy + [Text.Encoding]::UTF8.GetBytes('netguard-mac-v1'))
    [pscustomobject]@{ Enc = $encKey; Mac = $macKey }
}

function Protect-NGSecretBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [byte[]]$Entropy)
    if (-not $Entropy -or $Entropy.Length -eq 0) { throw 'Protect-NGSecretBytes requires key material.' }
    $keys = Get-NGDerivedKeys -Entropy $Entropy

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $keys.Enc
    $aes.GenerateIV()
    $iv = $aes.IV

    $enc = $aes.CreateEncryptor()
    $cipher = $enc.TransformFinalBlock($Bytes, 0, $Bytes.Length)
    $enc.Dispose(); $aes.Dispose()

    # Encrypt-then-MAC over IV||ciphertext, so tampering is detected before any
    # decryption is attempted.
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $keys.Mac)
    $tag = $hmac.ComputeHash($iv + $cipher)
    $hmac.Dispose()

    $iv + $tag + $cipher
}

function Unprotect-NGSecretBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [byte[]]$Entropy)
    if (-not $Entropy -or $Entropy.Length -eq 0) { throw 'Unprotect-NGSecretBytes requires key material.' }
    if ($Bytes.Length -lt 49) { throw 'Ciphertext is too short to be valid.' }
    $keys = Get-NGDerivedKeys -Entropy $Entropy

    $iv = $Bytes[0..15]
    $tag = $Bytes[16..47]
    $cipher = $Bytes[48..($Bytes.Length - 1)]

    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $keys.Mac)
    $expected = $hmac.ComputeHash($iv + $cipher)
    $hmac.Dispose()

    # Constant-time compare: a short-circuiting comparison leaks the tag byte by
    # byte to anyone who can time it.
    $diff = 0
    for ($i = 0; $i -lt $expected.Length; $i++) { $diff = $diff -bor ($expected[$i] -bxor $tag[$i]) }
    if ($diff -ne 0) { throw 'Secret store failed integrity check - wrong key or the file was tampered with.' }

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $keys.Enc
    $aes.IV = $iv
    $dec = $aes.CreateDecryptor()
    $plain = $dec.TransformFinalBlock($cipher, 0, $cipher.Length)
    $dec.Dispose(); $aes.Dispose()
    $plain
}

function Protect-NGFilePath {
    <# chmod 600 and chown root:root. Needs root to change ownership. #>
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    $chmod = Invoke-NGCommand -FilePath 'chmod' -Arguments @('600', $Path)
    if (-not $chmod.ok) { return $false }
    if (Test-NGElevated) {
        $chown = Invoke-NGCommand -FilePath 'chown' -Arguments @('root:root', $Path)
        return $chown.ok
    }
    # 0600 as a non-root user still restricts the file to that user, which is the
    # best available without privilege. Report false so the caller warns.
    $false
}

function Reset-NGFilePathAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    (Invoke-NGCommand -FilePath 'chmod' -Arguments @('644', $Path)).ok
}

# ============================================================== POSTURE ======

function Get-NGHostPosture {
    [CmdletBinding()]
    param()
    $p = New-NGPosture
    $p.elevated = Test-NGElevated

    # ------------------------------------------------------------ platform ---
    $osRelease = Get-NGFileTextSafe '/etc/os-release'
    if ($osRelease) {
        if ($osRelease -match '(?m)^PRETTY_NAME="?([^"\r\n]+)"?') { $p.platform.name = $Matches[1] }
        if ($osRelease -match '(?m)^VERSION_ID="?([^"\r\n]+)"?') { $p.platform.version = $Matches[1] }
        if ($osRelease -match '(?m)^ID=("?)([^"\r\n]+)\1') { $p.raw.distroId = $Matches[2] }
    }
    $p.platform.kernel = (Invoke-NGCommand -FilePath 'uname' -Arguments @('-r')).stdout.Trim()

    $uptimeText = Get-NGFileTextSafe '/proc/uptime'
    if ($uptimeText -and $uptimeText -match '^([\d.]+)') {
        $p.uptimeDays = [math]::Round(([double]$Matches[1]) / 86400, 1)
    }
    # A running desktop session is a reasonable proxy for "workstation".
    $p.platform.isServer = -not (Test-Path '/usr/bin/gnome-shell') -and -not (Test-Path '/usr/bin/plasmashell')

    # ----------------------------------------------------------- antivirus ---
    # ClamAV is the realistic option; most desktop Linux has nothing at all.
    $clamscan = Get-Command 'clamscan' -ErrorAction SilentlyContinue
    $freshclam = Get-Command 'freshclam' -ErrorAction SilentlyContinue
    $clamdState = Invoke-NGCommand -FilePath 'systemctl' -Arguments @('is-active', 'clamav-daemon')
    $onAccess = Invoke-NGCommand -FilePath 'systemctl' -Arguments @('is-active', 'clamav-clamonacc')

    if ($clamscan -or $freshclam) {
        $p.antivirus.present = $true
        $p.antivirus.product = 'ClamAV'
        $p.antivirus.readable = $true
        # On-access scanning is what "real-time" means here. clamav-daemon alone
        # only answers scan requests; clamonacc is the piece that intercepts.
        $p.antivirus.realtimeEnabled = ($onAccess.stdout.Trim() -eq 'active')
        # ClamAV has no tamper protection concept - leave $null, do not invent $false.
        foreach ($db in '/var/lib/clamav/daily.cvd', '/var/lib/clamav/daily.cld') {
            if (Test-Path $db) {
                $age = ((Get-Date) - (Get-Item $db).LastWriteTime).TotalDays
                $p.antivirus.signatureAgeDays = [int][math]::Floor($age)
                break
            }
        }
        $p.raw.clamdActive = $clamdState.stdout.Trim()
    }
    else {
        $p.antivirus.present = $false
        $p.antivirus.readable = $true
    }

    # ------------------------------------------------------------ firewall ---
    # Three possible front ends. Report whichever is actually in charge rather
    # than guessing, and mark unreadable when none can be queried.
    $ufw = Invoke-NGCommand -FilePath 'ufw' -Arguments @('status', 'verbose')
    $nft = Invoke-NGCommand -FilePath 'nft' -Arguments @('list', 'ruleset')
    $iptables = Invoke-NGCommand -FilePath 'iptables' -Arguments @('-S')
    $firewalld = Invoke-NGCommand -FilePath 'firewall-cmd' -Arguments @('--state')

    if ($ufw.found -and $ufw.ok) {
        $enabled = ($ufw.stdout -match '(?m)^Status:\s*active')
        $defaultIn = 'unknown'
        if ($ufw.stdout -match '(?m)^Default:\s*(\w+)\s*\(incoming\)') {
            $defaultIn = if ($Matches[1] -in 'deny', 'reject') { 'Block' } else { $Matches[1] }
        }
        $p.firewall = @([ordered]@{
                profile = 'ufw'; enabled = $enabled; defaultInbound = $defaultIn
                logging = ($ufw.stdout -match '(?m)^Logging:\s*on'); readable = $true
            })
    }
    elseif ($firewalld.found -and $firewalld.stdout.Trim() -eq 'running') {
        $zone = Invoke-NGCommand -FilePath 'firewall-cmd' -Arguments @('--get-default-zone')
        $p.firewall = @([ordered]@{
                profile = "firewalld/$($zone.stdout.Trim())"; enabled = $true
                defaultInbound = 'Block'; logging = $null; readable = $true
            })
    }
    elseif ($nft.found -and $nft.ok -and $nft.stdout.Trim()) {
        $policyDrop = ($nft.stdout -match 'hook input .* policy drop')
        $p.firewall = @([ordered]@{
                profile = 'nftables'; enabled = ($nft.stdout -match 'chain input')
                defaultInbound = $(if ($policyDrop) { 'Block' } else { 'Allow' })
                logging = ($nft.stdout -match '\blog\b'); readable = $true
            })
    }
    elseif ($iptables.found -and $iptables.ok) {
        $policyDrop = ($iptables.stdout -match '(?m)^-P INPUT (DROP|REJECT)')
        $ruleCount = (Get-NGCount @($iptables.stdout -split "`n" | Where-Object { $_ -match '^-A INPUT' }))
        $p.firewall = @([ordered]@{
                profile = 'iptables'; enabled = ($policyDrop -or $ruleCount -gt 0)
                defaultInbound = $(if ($policyDrop) { 'Block' } else { 'Allow' })
                logging = ($iptables.stdout -match '-j LOG'); readable = $true
            })
    }
    else {
        $p.firewall = @([ordered]@{
                profile = 'none detected'; enabled = $false; defaultInbound = 'Allow'
                logging = $false; readable = $true
            })
    }

    # ------------------------------------------------------ disk encryption --
    $lsblk = Invoke-NGCommand -FilePath 'lsblk' -Arguments @('-o', 'NAME,FSTYPE,MOUNTPOINT,TYPE', '-P')
    if ($lsblk.ok) {
        $crypt = @()
        foreach ($line in ($lsblk.stdout -split "`n")) {
            if ($line -match 'FSTYPE="crypto_LUKS"') {
                $nm = if ($line -match 'NAME="([^"]*)"') { $Matches[1] } else { 'unknown' }
                $crypt += [ordered]@{ mount = $nm; status = 'Encrypted'; method = 'LUKS'; readable = $true }
            }
        }
        # Only claim the root filesystem is unencrypted when we could actually
        # enumerate devices; otherwise stay silent.
        if ($crypt.Count -eq 0) {
            $rootDev = Invoke-NGCommand -FilePath 'findmnt' -Arguments @('-n', '-o', 'SOURCE', '/')
            $crypt += [ordered]@{
                mount = '/'; status = 'Unencrypted'; method = 'none'
                readable = ($rootDev.ok); device = $rootDev.stdout.Trim()
            }
        }
        $p.diskEncryption = $crypt
    }

    # ---------------------------------------------------------- secure boot --
    $mokutil = Invoke-NGCommand -FilePath 'mokutil' -Arguments @('--sb-state')
    if ($mokutil.found -and $mokutil.ok) {
        $p.secureBoot = ($mokutil.stdout -match 'SecureBoot enabled')
    }
    elseif (Test-Path '/sys/firmware/efi') {
        $efiVar = Get-ChildItem '/sys/firmware/efi/efivars' -Filter 'SecureBoot-*' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($efiVar) {
            try {
                $bytes = [IO.File]::ReadAllBytes($efiVar.FullName)
                if ($bytes.Length -ge 5) { $p.secureBoot = ($bytes[4] -eq 1) }
            }
            catch { }
        }
    }
    # No EFI at all means BIOS boot; Secure Boot is not applicable, so leave $null.

    # ------------------------------------------------------------- patching --
    $distro = "$($p.raw.distroId)"
    if ($distro -match 'debian|ubuntu|mint|pop|raspbian') {
        $stamp = '/var/lib/apt/periodic/update-success-stamp'
        if (-not (Test-Path $stamp)) { $stamp = '/var/cache/apt/pkgcache.bin' }
        if (Test-Path $stamp) {
            $p.patching.daysSinceLastUpdate = [int][math]::Floor(((Get-Date) - (Get-Item $stamp).LastWriteTime).TotalDays)
            $p.patching.readable = $true
        }
        # Count pending SECURITY updates specifically - total pending includes
        # cosmetic package churn and would cry wolf.
        $upgradable = Invoke-NGCommand -FilePath 'apt-get' -Arguments @('-s', '-q', 'upgrade') -TimeoutSeconds 45
        if ($upgradable.ok) {
            $p.patching.pendingSecurity = (Get-NGCount @($upgradable.stdout -split "`n" |
                    Where-Object { $_ -match '^Inst\b' -and $_ -match 'security' }))
        }
        $unattended = Get-NGFileTextSafe '/etc/apt/apt.conf.d/20auto-upgrades'
        if ($unattended) {
            $p.patching.autoUpdate = ($unattended -match 'Unattended-Upgrade"?\s+"1"')
        }
        else { $p.patching.autoUpdate = $false }
    }
    elseif ($distro -match 'rhel|centos|fedora|rocky|alma') {
        $dnfState = Invoke-NGCommand -FilePath 'systemctl' -Arguments @('is-enabled', 'dnf-automatic.timer')
        $p.patching.autoUpdate = ($dnfState.stdout.Trim() -eq 'enabled')
        $sec = Invoke-NGCommand -FilePath 'dnf' -Arguments @('-q', 'updateinfo', 'list', 'security') -TimeoutSeconds 60
        if ($sec.ok) {
            $p.patching.pendingSecurity = (Get-NGCount @($sec.stdout -split "`n" | Where-Object { $_.Trim() }))
            $p.patching.readable = $true
        }
    }

    # -------------------------------------------------------------- logging --
    # auditd with execve rules is the Linux equivalent of command-line auditing.
    $auditctl = Invoke-NGCommand -FilePath 'auditctl' -Arguments @('-l')
    if ($auditctl.found) {
        $p.logging.commandAuditing = ($auditctl.ok -and $auditctl.stdout -match 'execve')
    }
    else { $p.logging.commandAuditing = $false }

    # Shell command logging: auditd execve rules, or a system-wide bash trap.
    $bashLogging = Get-NGFileTextSafe '/etc/profile.d/netguard-audit.sh'
    $p.logging.scriptLogging = (($p.logging.commandAuditing -eq $true) -or ($null -ne $bashLogging))

    $journalConf = Get-NGFileTextSafe '/etc/systemd/journald.conf'
    if ($journalConf) {
        $persistent = ($journalConf -match '(?m)^\s*Storage\s*=\s*persistent') -or (Test-Path '/var/log/journal')
        $p.logging.adequateRetention = $persistent
        $p.raw.journalPersistent = $persistent
    }

    # -------------------------------------------------------- remote access --
    $sshdActive = Invoke-NGCommand -FilePath 'systemctl' -Arguments @('is-active', 'sshd')
    if (-not $sshdActive.ok) { $sshdActive = Invoke-NGCommand -FilePath 'systemctl' -Arguments @('is-active', 'ssh') }
    $p.remoteAccess.ssh.enabled = ($sshdActive.stdout.Trim() -eq 'active')

    if ($p.remoteAccess.ssh.enabled) {
        # sshd -T prints the EFFECTIVE config including defaults and Include
        # files, which reading sshd_config by hand would miss entirely.
        $sshdT = Invoke-NGCommand -FilePath 'sshd' -Arguments @('-T')
        if ($sshdT.ok) {
            $cfgText = $sshdT.stdout.ToLower()
            if ($cfgText -match '(?m)^permitrootlogin\s+(\S+)') { $p.remoteAccess.ssh.rootLogin = $Matches[1] }
            if ($cfgText -match '(?m)^passwordauthentication\s+(\S+)') {
                $p.remoteAccess.ssh.passwordAuth = ($Matches[1] -eq 'yes')
            }
            if ($cfgText -match '(?m)^port\s+(\d+)') { $p.remoteAccess.ssh.port = [int]$Matches[1] }
            $p.raw.sshdEffective = [ordered]@{
                permitEmptyPasswords = ($cfgText -match '(?m)^permitemptypasswords\s+yes')
                x11Forwarding        = ($cfgText -match '(?m)^x11forwarding\s+yes')
                maxAuthTries         = $(if ($cfgText -match '(?m)^maxauthtries\s+(\d+)') { [int]$Matches[1] } else { $null })
            }
        }
    }

    # --------------------------------------------------------------- shares --
    $exports = Get-NGFileTextSafe '/etc/exports'
    if ($exports) {
        $p.shares = @($exports -split "`n" | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') } |
            ForEach-Object { [ordered]@{ name = 'nfs'; path = ($_ -split '\s+')[0]; description = $_.Trim() } })
    }
    $smbConf = Get-NGFileTextSafe '/etc/samba/smb.conf'
    if ($smbConf) {
        foreach ($m in [regex]::Matches($smbConf, '(?m)^\[([^\]]+)\]')) {
            if ($m.Groups[1].Value -in 'global', 'printers', 'print$') { continue }
            $p.shares += [ordered]@{ name = $m.Groups[1].Value; path = ''; description = 'samba share' }
        }
    }

    # ------------------------------------------------------------ MAC / LSM --
    $aa = Invoke-NGCommand -FilePath 'aa-status' -Arguments @('--enabled')
    $sestatus = Invoke-NGCommand -FilePath 'getenforce'
    $p.raw.mandatoryAccessControl = [ordered]@{
        apparmorEnabled = $(if ($aa.found) { $aa.ok } else { $null })
        selinuxMode     = $(if ($sestatus.found -and $sestatus.ok) { $sestatus.stdout.Trim() } else { $null })
    }

    # ------------------------------------------------------- kernel sysctls --
    # One sysctl invocation for all keys rather than ten process spawns - this
    # was a measurable share of a 7-second posture collection.
    $sysctlKeys = @('kernel.randomize_va_space', 'kernel.kptr_restrict', 'kernel.dmesg_restrict',
        'kernel.unprivileged_bpf_disabled', 'net.ipv4.conf.all.accept_redirects',
        'net.ipv4.conf.all.rp_filter', 'net.ipv4.tcp_syncookies', 'fs.protected_hardlinks',
        'fs.protected_symlinks', 'kernel.yama.ptrace_scope')
    $sysctls = [ordered]@{}
    foreach ($k in $sysctlKeys) { $sysctls[$k] = $null }
    $bulk = Invoke-NGCommand -FilePath 'sysctl' -Arguments $sysctlKeys
    if ($bulk.found) {
        foreach ($line in ($bulk.stdout -split "`n")) {
            if ($line -match '^\s*([\w.]+)\s*=\s*(.+?)\s*$') {
                $key = $Matches[1]
                if ($sysctls.Contains($key)) { $sysctls[$key] = $Matches[2].Trim() }
            }
        }
    }
    $p.raw.sysctl = $sysctls

    # --------------------------------------------------------- sudo / users --
    if ($p.elevated) {
        $sudoers = @()
        foreach ($file in @('/etc/sudoers') + @(Get-ChildItem '/etc/sudoers.d' -File -ErrorAction SilentlyContinue |
                ForEach-Object { $_.FullName })) {
            $txt = Get-NGFileTextSafe $file
            if (-not $txt) { continue }
            foreach ($line in ($txt -split "`n")) {
                $t = $line.Trim()
                if ($t -and -not $t.StartsWith('#') -and $t -match 'NOPASSWD') {
                    $sudoers += [ordered]@{ file = $file; rule = $t }
                }
            }
        }
        $p.raw.sudoNoPasswd = $sudoers
    }

    $p
}

# ============================================================== NETWORK ======

function Get-NGLocalSubnet {
    <#
        Primary physical LAN, skipping virtual/container bridges. Without this
        filter, Docker's 172.17.0.0/16 is usually picked and discovery sweeps an
        empty bridge instead of the real network.
    #>
    $virtualPattern = '^(docker|br-|veth|virbr|lo|tun|tap|wg|zt|tailscale|vmnet|kube|cni|flannel|cali)'
    $route = Invoke-NGCommand -FilePath 'ip' -Arguments @('-o', '-4', 'route', 'show', 'default')
    if (-not $route.ok) { return $null }

    foreach ($line in ($route.stdout -split "`n")) {
        if ($line -notmatch 'default via (\S+) dev (\S+)') { continue }
        $gw = $Matches[1]; $iface = $Matches[2]
        if ($iface -match $virtualPattern) { continue }

        $addr = Invoke-NGCommand -FilePath 'ip' -Arguments @('-o', '-4', 'addr', 'show', 'dev', $iface)
        if (-not $addr.ok) { continue }
        if ($addr.stdout -notmatch 'inet (\d+\.\d+\.\d+\.\d+)/(\d+)') { continue }
        $ip = $Matches[1]; $prefix = [int]$Matches[2]
        $octets = $ip.Split('.')
        # The subnet is returned whatever its size. Only the host-by-host SWEEP
        # needs a narrow prefix; rejecting a /20 outright also disabled the
        # gateway, UPnP and external-IP checks, which do not care how big the
        # network is. WSL and most container hosts sit on a /20.
        return [pscustomobject]@{
            Interface = $iface
            IPAddress = $ip
            Prefix    = $prefix
            Gateway   = $gw
            Base      = ('{0}.{1}.{2}' -f $octets[0], $octets[1], $octets[2])
            Cidr      = ('{0}.{1}.{2}.0/{3}' -f $octets[0], $octets[1], $octets[2], $prefix)
            Sweepable = ($prefix -ge 22)
        }
    }
    $null
}

function Get-NGAddressScopeMap {
    $virtualPattern = '^(docker|br-|veth|virbr|tun|tap|wg|zt|tailscale|vmnet|kube|cni|flannel|cali)'
    $map = @{}
    $addr = Invoke-NGCommand -FilePath 'ip' -Arguments @('-o', 'addr', 'show')
    if (-not $addr.ok) { return $map }
    foreach ($line in ($addr.stdout -split "`n")) {
        if ($line -match '^\d+:\s+(\S+)\s+inet6?\s+([0-9a-f.:]+)/') {
            $iface = $Matches[1]; $ip = $Matches[2]
            $map[$ip] = [pscustomobject]@{
                interface = $iface
                scope     = if ($iface -match $virtualPattern) { 'virtual' } else { 'lan' }
            }
        }
    }
    $map
}

function Get-NGListeningPorts {
    [CmdletBinding()]
    param()
    # ss is the modern replacement for netstat and is present on every systemd
    # distro. -p needs root to attribute sockets to processes; without it the
    # process shows as unknown rather than the collector failing.
    $ss = Invoke-NGCommand -FilePath 'ss' -Arguments @('-tulpnH')
    if (-not $ss.ok) {
        $ss = Invoke-NGCommand -FilePath 'ss' -Arguments @('-tulnH')
        if (-not $ss.ok) { return @() }
    }
    $scopeMap = Get-NGAddressScopeMap
    $out = New-Object System.Collections.Generic.List[psobject]

    foreach ($line in ($ss.stdout -split "`n")) {
        $t = $line.Trim()
        if (-not $t) { continue }
        $cols = $t -split '\s+'
        if ($cols.Count -lt 5) { continue }

        $proto = $cols[0].ToUpper()
        if ($proto -notin 'TCP', 'UDP') { continue }
        $local = $cols[4]

        # IPv6 literals are bracketed: [::]:22 . IPv4 is plain: 0.0.0.0:22 .
        $addr = $null; $port = $null
        if ($local -match '^\[(.+)\]:(\d+)$') { $addr = $Matches[1]; $port = [int]$Matches[2] }
        elseif ($local -match '^(.+):(\d+)$') { $addr = $Matches[1]; $port = [int]$Matches[2] }
        else { continue }
        if ($addr -eq '*') { $addr = '0.0.0.0' }

        $procName = 'unknown'; $procPid = 0; $procPath = $null
        if ($t -match 'users:\(\("([^"]+)",pid=(\d+)') {
            $procName = $Matches[1]
            $procPid = [int]$Matches[2]
            try { $procPath = (Get-Item "/proc/$procPid/exe" -ErrorAction Stop).Target } catch { }
        }

        $scope = if ($addr -in '127.0.0.1', '::1') { 'loopback' }
                 elseif ($addr -in '0.0.0.0', '::') { 'any' }
                 elseif ($addr -like 'fe80:*' -or $addr -like '169.254.*') { 'linklocal' }
                 elseif ($scopeMap.ContainsKey($addr)) { $scopeMap[$addr].scope }
                 else { 'other' }

        $out.Add([pscustomobject][ordered]@{
                protocol     = $proto
                localAddress = $addr
                port         = $port
                processId    = $procPid
                processName  = $procName
                processPath  = $procPath
                scope        = $scope
                loopbackOnly = ($scope -eq 'loopback')
                reachable    = ($scope -in 'any', 'lan')
                key          = "$proto/$port/$addr"
            })
    }
    , @($out | Sort-Object protocol, port)
}

function Get-NGLanDevices {
    [CmdletBinding()]
    param([switch]$SkipSweep, [int]$SweepTimeoutMs = 400)

    $subnet = Get-NGLocalSubnet
    if (-not $subnet) { return @() }

    if (-not $subnet.Sweepable) {
        Write-NGLog "LAN $($subnet.Cidr) is wider than /22; skipping the host sweep and using the neighbour table only." -Level DEBUG -Agent discovery -Quiet
        $SkipSweep = $true
    }
    if (-not $SkipSweep) {
        # Async pings prime the ARP/neighbour table; a /24 finishes in about a
        # second instead of two minutes sequentially.
        $pings = @()
        foreach ($i in 1..254) {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $pings += [pscustomobject]@{ Ping = $ping; Task = $ping.SendPingAsync("$($subnet.Base).$i", $SweepTimeoutMs) }
        }
        try { [Threading.Tasks.Task]::WaitAll(@($pings.Task), ($SweepTimeoutMs + 1500)) } catch { }
        foreach ($pg in $pings) { try { $pg.Ping.Dispose() } catch { } }
    }

    $neigh = Invoke-NGCommand -FilePath 'ip' -Arguments @('-o', 'neigh', 'show')
    if (-not $neigh.ok) { return @() }

    $out = New-Object System.Collections.Generic.List[psobject]
    foreach ($line in ($neigh.stdout -split "`n")) {
        if ($line -notmatch '^(\S+)\s+dev\s+(\S+)\s+lladdr\s+(\S+)\s+(\w+)') { continue }
        $ip = $Matches[1]; $mac = $Matches[3].ToUpper(); $state = $Matches[4]
        if ($state -eq 'FAILED' -or $state -eq 'INCOMPLETE') { continue }
        if ($ip -notlike "$($subnet.Base).*") { continue }

        $hostname = $null
        try { $hostname = [Net.Dns]::GetHostEntry($ip).HostName } catch { }
        $out.Add([pscustomobject][ordered]@{
                mac = $mac; ipAddress = $ip; hostName = $hostname
                vendor = (Get-NGVendorFromMac $mac); state = $state
                isGateway = ($ip -eq $subnet.Gateway)
                firstSeen = (Get-Date).ToUniversalTime().ToString('o')
                lastSeen = (Get-Date).ToUniversalTime().ToString('o')
            })
    }
    , @($out)
}

function Get-NGSignatureStatus {
    <#
        Linux has no per-binary Authenticode equivalent. Package-manager
        ownership is the closest honest answer: a binary a package owns came
        from a signed repository, one that no package owns did not.

        Reported as supported=$false so the scan scorer does not penalise every
        file for being unsigned the way it would on Windows.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    $owner = $null
    $dpkg = Invoke-NGCommand -FilePath 'dpkg' -Arguments @('-S', $Path)
    if ($dpkg.ok -and $dpkg.stdout) { $owner = ($dpkg.stdout -split ':')[0].Trim() }
    else {
        $rpm = Invoke-NGCommand -FilePath 'rpm' -Arguments @('-qf', $Path)
        if ($rpm.ok -and $rpm.stdout -notmatch 'not owned') { $owner = $rpm.stdout.Trim() }
    }
    [pscustomobject]@{
        status      = if ($owner) { 'PackageOwned' } else { 'Unowned' }
        signer      = $owner
        issuer      = $null
        thumbprint  = $null
        notAfter    = $null
        timeStamped = $false
        supported   = $false
    }
}

# ========================================================== PERSISTENCE ======

function Get-NGAutoruns {
    [CmdletBinding()]
    param()
    $items = New-Object System.Collections.Generic.List[psobject]

    # --- systemd units (enabled only; disabled units do not run)
    $units = Invoke-NGCommand -FilePath 'systemctl' -Arguments @(
        'list-unit-files', '--type=service,timer', '--state=enabled', '--no-legend', '--no-pager') -TimeoutSeconds 30
    if ($units.ok) {
        foreach ($line in ($units.stdout -split "`n")) {
            $t = $line.Trim()
            if (-not $t) { continue }
            $unitName = ($t -split '\s+')[0]
            if (-not $unitName) { continue }
            $show = Invoke-NGCommand -FilePath 'systemctl' -Arguments @(
                'show', $unitName, '-p', 'ExecStart', '-p', 'FragmentPath', '--value', '--no-pager')
            $exec = ''; $frag = ''
            if ($show.ok) {
                $lines = @($show.stdout -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                if ($lines.Count -ge 1) { $exec = $lines[0] }
                if ($lines.Count -ge 2) { $frag = $lines[1] }
            }
            $type = if ($unitName -like '*.timer') { 'SystemdTimer' } else { 'SystemdUnit' }
            $items.Add([pscustomobject][ordered]@{
                    type = $type; location = $frag; name = $unitName
                    command = $exec; key = "$type|$unitName"
                })
        }
    }

    # --- cron: system table, drop-ins, and per-user crontabs
    foreach ($cronFile in @('/etc/crontab') +
        @(Get-ChildItem '/etc/cron.d' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })) {
        $txt = Get-NGFileTextSafe $cronFile
        if (-not $txt) { continue }
        foreach ($line in ($txt -split "`n")) {
            $t = $line.Trim()
            if (-not $t -or $t.StartsWith('#') -or $t -match '^\w+\s*=') { continue }
            $items.Add([pscustomobject][ordered]@{
                    type = 'Cron'; location = $cronFile; name = ($t -split '\s+' | Select-Object -Last 1)
                    command = $t; key = "Cron|$cronFile|$t"
                })
        }
    }
    foreach ($dir in '/var/spool/cron/crontabs', '/var/spool/cron') {
        foreach ($uf in (Get-ChildItem $dir -File -ErrorAction SilentlyContinue)) {
            $txt = Get-NGFileTextSafe $uf.FullName
            if (-not $txt) { continue }
            foreach ($line in ($txt -split "`n")) {
                $t = $line.Trim()
                if (-not $t -or $t.StartsWith('#') -or $t -match '^\w+\s*=') { continue }
                $items.Add([pscustomobject][ordered]@{
                        type = 'Cron'; location = "user:$($uf.Name)"; name = $uf.Name
                        command = $t; key = "Cron|$($uf.Name)|$t"
                    })
            }
        }
    }

    # --- shell profiles. A line appended to .bashrc is the Linux equivalent of a
    #     Run key and is routinely missed because nobody diffs dotfiles.
    $profileFiles = @('/etc/profile', '/etc/bash.bashrc', '/etc/zsh/zshrc') +
        @(Get-ChildItem '/etc/profile.d' -File -Filter '*.sh' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    foreach ($home in (Get-ChildItem '/home' -Directory -ErrorAction SilentlyContinue)) {
        foreach ($rc in '.bashrc', '.bash_profile', '.profile', '.zshrc', '.bash_login') {
            $profileFiles += (Join-Path $home.FullName $rc)
        }
    }
    foreach ($rc in '.bashrc', '.bash_profile', '.profile', '.zshrc') {
        $profileFiles += (Join-Path '/root' $rc)
    }
    foreach ($pf in $profileFiles) {
        $txt = Get-NGFileTextSafe $pf
        if (-not $txt) { continue }
        foreach ($line in ($txt -split "`n")) {
            $t = $line.Trim()
            if (-not $t -or $t.StartsWith('#')) { continue }
            # Only executable-looking lines; plain exports are noise.
            if ($t -match '^\s*(export|alias|umask|PATH=|#)' ) { continue }
            if ($t -match '^(source|\.|eval|curl|wget|nc|bash|sh|python|perl|/)' -or $t -match '\|\s*(sh|bash)') {
                $items.Add([pscustomobject][ordered]@{
                        type = 'ShellProfile'; location = $pf; name = (Split-Path $pf -Leaf)
                        command = $t; key = "ShellProfile|$pf|$t"
                    })
            }
        }
    }

    # --- rc.local and init scripts
    foreach ($rcFile in '/etc/rc.local', '/etc/rc.d/rc.local') {
        $txt = Get-NGFileTextSafe $rcFile
        if (-not $txt) { continue }
        foreach ($line in ($txt -split "`n")) {
            $t = $line.Trim()
            if (-not $t -or $t.StartsWith('#') -or $t -eq 'exit 0') { continue }
            $items.Add([pscustomobject][ordered]@{
                    type = 'RcLocal'; location = $rcFile; name = 'rc.local'
                    command = $t; key = "RcLocal|$t"
                })
        }
    }

    # --- systemd user units (survive as the user, often missed)
    foreach ($base in @('/home', '/root')) {
        foreach ($home in (Get-ChildItem $base -Directory -ErrorAction SilentlyContinue)) {
            $userUnitDir = Join-Path $home.FullName '.config/systemd/user'
            foreach ($u in (Get-ChildItem $userUnitDir -File -ErrorAction SilentlyContinue)) {
                $txt = Get-NGFileTextSafe $u.FullName
                $exec = ''
                if ($txt -and $txt -match '(?m)^ExecStart\s*=\s*(.+)$') { $exec = $Matches[1].Trim() }
                $items.Add([pscustomobject][ordered]@{
                        type = 'SystemdUserUnit'; location = $u.FullName; name = $u.Name
                        command = $exec; key = "SystemdUserUnit|$($u.FullName)"
                    })
            }
        }
    }

    # --- LD_PRELOAD: a single line here hijacks every dynamically linked binary
    $ldPreload = Get-NGFileTextSafe '/etc/ld.so.preload'
    if ($ldPreload -and $ldPreload.Trim()) {
        foreach ($line in ($ldPreload -split "`n")) {
            $t = $line.Trim()
            if (-not $t) { continue }
            $items.Add([pscustomobject][ordered]@{
                    type = 'LdPreload'; location = '/etc/ld.so.preload'; name = 'ld.so.preload'
                    command = $t; key = "LdPreload|$t"
                })
        }
    }

    , @($items)
}

function Get-NGLocalAccounts {
    [CmdletBinding()]
    param()
    $passwd = Get-NGFileTextSafe '/etc/passwd'
    if (-not $passwd) { return [pscustomobject]@{ users = @(); adminMembers = @(); remoteUsers = @() } }

    # Shadow is root-only; without it we cannot tell locked from passwordless,
    # so those fields stay $null rather than guessing.
    $shadow = @{}
    $shadowText = Get-NGFileTextSafe '/etc/shadow'
    if ($shadowText) {
        foreach ($line in ($shadowText -split "`n")) {
            $parts = $line -split ':'
            if ($parts.Count -ge 2) { $shadow[$parts[0]] = $parts[1] }
        }
    }

    # Admin = member of a sudo-capable group.
    $adminMembers = @()
    $groupText = Get-NGFileTextSafe '/etc/group'
    $adminGroups = @('sudo', 'wheel', 'admin', 'root')
    if ($groupText) {
        foreach ($line in ($groupText -split "`n")) {
            $parts = $line -split ':'
            if ($parts.Count -ge 4 -and $parts[0] -in $adminGroups) {
                foreach ($m in ($parts[3] -split ',')) { if ($m.Trim()) { $adminMembers += $m.Trim() } }
            }
        }
    }

    $users = New-Object System.Collections.Generic.List[psobject]
    foreach ($line in ($passwd -split "`n")) {
        $parts = $line -split ':'
        if ($parts.Count -lt 7) { continue }
        $name = $parts[0]; $uid = [int]$parts[2]; $shell = $parts[6]

        # A nologin/false shell means the account cannot be used interactively.
        $canLogin = ($shell -notmatch 'nologin|/bin/false|/bin/sync')
        $hash = $shadow[$name]
        $enabled = $null
        $passwordRequired = $null
        if ($null -ne $hash) {
            # ! or * prefix = locked. Empty = no password at all.
            $locked = ($hash.StartsWith('!') -or $hash.StartsWith('*'))
            $enabled = ($canLogin -and -not $locked)
            $passwordRequired = -not ([string]::IsNullOrEmpty($hash))
        }
        elseif (-not $canLogin) { $enabled = $false }

        $users.Add([pscustomobject][ordered]@{
                name             = $name
                uid              = $uid
                enabled          = $enabled
                isAdmin          = (($name -in $adminMembers) -or ($uid -eq 0))
                passwordRequired = $passwordRequired
                shell            = $shell
                home             = $parts[5]
                isSystemAccount  = ($uid -lt 1000 -and $uid -ne 0)
                isBuiltinAdmin   = ($uid -eq 0 -and $name -eq 'root')
                key              = "uid:$uid|$name"
            })
    }

    # uid 0 is administrative by definition, whether or not it appears in a group.
    foreach ($u in $users) {
        if ($u.uid -eq 0 -and $u.name -notin $adminMembers) { $adminMembers += $u.name }
    }

    [pscustomobject]@{
        users        = @($users)
        adminMembers = @($adminMembers | Sort-Object -Unique)
        remoteUsers  = @($users | Where-Object { $_.enabled -eq $true } | ForEach-Object { $_.name })
    }
}

function Get-NGTrustedCertificates {
    <#
        The system CA bundle. A certificate added here is trusted by curl, wget,
        most language runtimes and anything else using the OpenSSL defaults - the
        same silent-TLS-interception risk as a rogue Windows root.
    #>
    [CmdletBinding()]
    param()
    $out = New-Object System.Collections.Generic.List[psobject]
    $storeDirs = @(
        @{ path = '/usr/local/share/ca-certificates'; managed = $false }   # operator-added
        @{ path = '/etc/pki/ca-trust/source/anchors'; managed = $false }   # operator-added (RHEL)
        @{ path = '/usr/share/ca-certificates';       managed = $true }    # distro-shipped
    )

    foreach ($store in $storeDirs) {
        if (-not (Test-Path $store.path)) { continue }
        foreach ($file in (Get-ChildItem $store.path -Recurse -File -ErrorAction SilentlyContinue)) {
            if ($file.Extension -notin '.crt', '.pem', '.cer') { continue }
            try {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($file.FullName)
                $out.Add([pscustomobject][ordered]@{
                        store = $store.path; subject = $cert.Subject; issuer = $cert.Issuer
                        thumbprint = $cert.Thumbprint; notBefore = $cert.NotBefore; notAfter = $cert.NotAfter
                        selfSigned = ($cert.Subject -eq $cert.Issuer)
                        systemManaged = $store.managed
                        key = "$($store.path)|$($cert.Thumbprint)"
                    })
                $cert.Dispose()
            }
            catch { }
        }
    }
    , @($out)
}

function Get-NGHostsFileEntries {
    $txt = Get-NGFileTextSafe '/etc/hosts'
    if (-not $txt) { return @() }
    $out = @($txt -split "`n" | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith('#')) { [pscustomobject]@{ entry = $line; key = $line } }
        })
    , @($out)
}

# =============================================================== EVENTS ======

function Get-NGSecurityEvents {
    <#
        Structured journal triage.

        Reads journalctl as JSON and matches on the SYSLOG_IDENTIFIER field plus
        the message, never on free text anywhere in a rendered log line.

        This is a security property, not a style choice. With free-text matching,
        anything that can write to syslog - a web app logging a request path, a
        crashing process dumping a buffer, a user echoing a string - can forge a
        detection. During testing, PowerShell source text that landed in the
        journal produced a Critical "security audit log was cleared" alert three
        times over. Anchoring to the identifier means only the program that
        actually performs an action can report having performed it.
    #>
    [CmdletBinding()]
    param([int]$SinceMinutes = 20)

    # Absolute timestamp, not "-20min": journalctl parses a leading dash as an
    # option bundle and the relative form is ambiguous across versions.
    $sinceStamp = (Get-Date).AddMinutes(-$SinceMinutes).ToString('yyyy-MM-dd HH:mm:ss')

    $result = [ordered]@{
        windowMinutes = $SinceMinutes
        since = (Get-Date).AddMinutes(-$SinceMinutes).ToString('o')
        failedLogons = @(); logCleared = @(); accountChanges = @(); newScheduledTasks = @()
        newServices = @(); avDetections = @(); suspiciousExecution = @(); remoteLogons = @()
    }

    $journal = Invoke-NGCommand -FilePath 'journalctl' -Arguments @(
        '--since', $sinceStamp, '--no-pager', '--quiet', '-o', 'json',
        '--output-fields=SYSLOG_IDENTIFIER,MESSAGE,_COMM,_PID') -TimeoutSeconds 60

    $records = New-Object System.Collections.Generic.List[psobject]
    if ($journal.ok) {
        foreach ($line in ($journal.stdout -split "`n")) {
            if (-not $line.Trim().StartsWith('{')) { continue }
            try { $rec = $line | ConvertFrom-Json } catch { continue }

            # MESSAGE is a byte array when the payload is not valid UTF-8.
            $msg = $rec.MESSAGE
            if ($msg -is [array]) {
                try { $msg = [Text.Encoding]::UTF8.GetString([byte[]]$msg) } catch { $msg = '' }
            }
            $ident = "$($rec.SYSLOG_IDENTIFIER)"
            if (-not $ident) { $ident = "$($rec._COMM)" }
            $records.Add([pscustomobject]@{
                    identifier = $ident.ToLower()
                    message    = "$msg"
                    pid        = $rec._PID
                })
        }
    }

    function _from { param([string[]]$Identifiers) @($records | Where-Object { $_.identifier -in $Identifiers }) }

    $now = (Get-Date).ToString('o')

    # --- failed authentication. Only the authenticating daemon may report one.
    $authRecords = _from @('sshd', 'sudo', 'su', 'login', 'systemd-logind', 'polkitd', 'gdm-password')
    foreach ($r in $authRecords) {
        if ($r.message -match '^Failed password for (?:invalid user )?(\S+) from (\S+)') {
            $result.failedLogons += [pscustomobject]@{
                time = $now; target = $Matches[1]; source = $Matches[2]; method = 'SSH'
            }
        }
        elseif ($r.identifier -eq 'sudo' -and $r.message -match 'authentication failure.*user=(\S+)') {
            $result.failedLogons += [pscustomobject]@{
                time = $now; target = $Matches[1]; source = 'local'; method = 'sudo'
            }
        }
        elseif ($r.message -match '^(?:pam_unix\(\S+\):\s*)?authentication failure;.*rhost=(\S*).*user=(\S+)') {
            $src = if ($Matches[1]) { $Matches[1] } else { 'local' }
            $result.failedLogons += [pscustomobject]@{
                time = $now; target = $Matches[2]; source = $src; method = 'PAM'
            }
        }
    }

    # --- deliberate log destruction. Routine rotation and size-based vacuuming
    # are normal housekeeping and must not fire.
    foreach ($r in (_from @('journalctl', 'auditd', 'auditctl', 'systemd-journald'))) {
        if ($r.identifier -eq 'systemd-journald' -and $r.message -notmatch 'Permanent journal .* removed|corrupted') { continue }
        if ($r.message -match 'Vacuuming done.*--vacuum-(time|size|files)' -or
            $r.message -match 'audit (log|rules).*(cleared|truncated|deleted)' -or
            $r.message -match 'Stopped Security Auditing Service' -or
            $r.message -match 'Permanent journal .* removed') {
            $result.logCleared += [pscustomobject]@{ time = $now; message = $r.message }
        }
    }

    # --- account and group changes
    foreach ($r in (_from @('useradd', 'usermod', 'userdel', 'groupadd', 'groupdel', 'gpasswd', 'chpasswd', 'passwd'))) {
        $result.accountChanges += [pscustomobject]@{
            time = $now; id = $r.identifier; message = $r.message
        }
    }

    # --- newly INSTALLED systemd units.
    # "Started X" is not "installed X"; every boot starts dozens of units, which
    # produced 48 findings in one 20-minute window. A unit FILE appearing is the
    # real event. Ongoing drift is also covered by the autoruns baseline.
    $unitCutoff = (Get-Date).AddMinutes(-$SinceMinutes)
    foreach ($dir in '/etc/systemd/system', '/run/systemd/system', '/usr/local/lib/systemd/system') {
        foreach ($u in (Get-ChildItem $dir -File -ErrorAction SilentlyContinue)) {
            if ($u.LastWriteTime -lt $unitCutoff) { continue }
            $exec = ''
            $txt = Get-NGFileTextSafe $u.FullName
            if ($txt -and $txt -match '(?m)^ExecStart\s*=\s*(.+)$') { $exec = $Matches[1].Trim() }
            $result.newServices += [pscustomobject]@{
                time = $u.LastWriteTime.ToString('o'); serviceName = $u.Name
                imagePath = $exec; startType = 'systemd'
            }
        }
    }

    # --- antivirus events
    foreach ($r in (_from @('clamd', 'clamonacc', 'freshclam', 'clamav-daemon', 'clamdscan'))) {
        if ($r.message -match '\bFOUND\b') {
            $result.avDetections += [pscustomobject]@{
                time = $now; id = 'clamav'; kind = 'malware-detected'; message = $r.message
            }
        }
        elseif ($r.message -match 'Stopped ClamAV|daemon.*(failed|terminated)') {
            $result.avDetections += [pscustomobject]@{
                time = $now; id = 'clamav'; kind = 'protection-disabled'; message = $r.message
            }
        }
    }

    <#
        Suspicious command execution from auditd EXECVE records.

        Same discipline as the Windows script-block triage: ONE high-confidence
        indicator or TWO weak ones, never NetGuard's own commands, and identical
        commands collapsed. Without that, this rule detects the monitoring tool
        itself on every run.
    #>
    $highConfidence = @(
        'curl\s+[^|]*\|\s*(sudo\s+)?(ba)?sh'
        'wget\s+[^|]*\|\s*(sudo\s+)?(ba)?sh'
        'base64\s+(-d|--decode)[^|]*\|\s*(ba)?sh'
        'nc\s+-[a-z]*e\s|ncat\s+.*--exec'
        '/dev/tcp/\d|bash\s+-i\s+>&'
        'chattr\s+\+i\s+/etc|history\s+-c|unset\s+HISTFILE'
        'insmod\s|modprobe\s+.*rootkit'
        'echo\s+.*>>\s*/etc/ld\.so\.preload'
    )
    $weak = @('base64\s+(-d|--decode)', 'curl\s+-s', 'wget\s+-q', 'chmod\s+\+x\s+/tmp/',
        '/dev/shm/', 'python\s+-c\s+.import', 'perl\s+-e', 'setsid', 'nohup\s')
    $selfPattern = 'netguard|NetGuard|Invoke-NGCommand|Test-NetGuard|Probe-Provider|Probe-Events'

    $ausearch = Invoke-NGCommand -FilePath 'ausearch' -Arguments @('-m', 'EXECVE', '-ts', 'recent', '-i') -TimeoutSeconds 30
    $blocks = @{}
    if ($ausearch.ok) {
        foreach ($rec in ($ausearch.stdout -split '----')) {
            if (-not $rec.Trim()) { continue }
            if ($rec -match $selfPattern) { continue }
            $cmd = ''
            foreach ($m in [regex]::Matches($rec, 'a\d+="([^"]*)"')) { $cmd += $m.Groups[1].Value + ' ' }
            $cmd = $cmd.Trim()
            if (-not $cmd) { continue }

            $hits = @(); $isHigh = $false
            foreach ($rx in $highConfidence) { if ($cmd -match $rx) { $isHigh = $true; $hits += "high:$rx" } }
            foreach ($rx in $weak) { if ($cmd -match $rx) { $hits += "weak:$rx" } }
            if (-not $isHigh -and (Get-NGCount @($hits | Where-Object { $_ -like 'weak:*' })) -lt 2) { continue }

            $sha = [System.Security.Cryptography.SHA256]::Create()
            $k = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($cmd))) -replace '-', '').Substring(0, 16)
            if ($blocks.ContainsKey($k)) { $blocks[$k].occurrences++; continue }
            $blocks[$k] = [pscustomobject]@{
                time = $now; source = 'shell command'; command = $cmd
                confidence = $(if ($isHigh) { 'high' } else { 'medium' })
                indicators = $hits; occurrences = 1
            }
        }
    }
    $result.suspiciousExecution = @($blocks.Values)

    # --- successful interactive remote logons. Only sshd may report one.
    foreach ($r in (_from @('sshd'))) {
        if ($r.message -match '^Accepted (password|publickey|keyboard-interactive\S*) for (\S+) from (\S+)') {
            $result.remoteLogons += [pscustomobject]@{
                time = $now; method = 'SSH'
                user = $Matches[2]; source = $Matches[3]; auth = $Matches[1]
            }
        }
    }

    [pscustomobject]$result
}

# ========================================================== AV SCANNING ======

function Invoke-NGAntivirusScan {
    <#
        On-demand ClamAV scan of one file.

        The verdict comes from the OUTPUT TEXT as well as the exit code. clamscan
        uses 0 = clean, 1 = infected, 2 = error - and treating "error" as
        "infected" would quarantine every clean file when the daemon is down,
        which is exactly the bug the Windows provider had. Anything not
        positively classified stays $null and is excluded from scoring.
    #>
    param([Parameter(Mandatory = $true)][string]$Path, [int]$TimeoutSeconds = 120)

    # clamdscan is far faster when the daemon is up; fall back to clamscan.
    $engine = 'clamdscan'
    $r = Invoke-NGCommand -FilePath 'clamdscan' -Arguments @('--no-summary', '--fdpass', $Path) -TimeoutSeconds $TimeoutSeconds
    if (-not $r.found) {
        $engine = 'clamscan'
        $r = Invoke-NGCommand -FilePath 'clamscan' -Arguments @('--no-summary', $Path) -TimeoutSeconds $TimeoutSeconds
    }
    if (-not $r.found) {
        return [pscustomobject]@{ ran = $false; clean = $null; engine = 'none'
                                  detail = 'No antivirus scanner installed (try: apt install clamav)' }
    }

    $flat = (($r.stdout + ' ' + $r.stderr) -replace '\s+', ' ').Trim()
    $clean = $null
    if ($flat -match ':\s*OK\s*$' -or $flat -match ':\s*OK\b') { $clean = $true }
    elseif ($flat -match ':\s*(.+)\s+FOUND') { $clean = $false }
    elseif ($r.exitCode -eq 0) { $clean = $true }
    elseif ($r.exitCode -eq 1) { $clean = $false }
    # exitCode 2 (or anything else) is an ERROR, not a detection: stays $null.

    [pscustomobject]@{
        ran = ($null -ne $clean); clean = $clean; engine = $engine
        exitCode = $r.exitCode; detail = $flat
    }
}

# ============================================================ SCHEDULING =====

function Register-NGSchedule {
    <#
        systemd timers rather than cron: they survive downtime via Persistent=true,
        log to the journal, and can be queried for last/next run - none of which
        cron offers.
    #>
    param([Parameter(Mandatory = $true)]$Jobs, [string]$NGRoot, [string]$UserPrincipal)

    $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if (-not $pwshPath) { throw 'pwsh not found on PATH; cannot register systemd units.' }
    $unitDir = '/etc/systemd/system'
    $registered = @()

    foreach ($j in $Jobs) {
        $scriptPath = Join-Path $NGRoot $j.Script
        if (-not (Test-Path $scriptPath)) { continue }
        $unitName = "netguard-$($j.Name.ToLower())"
        $execArgs = "-NoProfile -NonInteractive -File `"$scriptPath`""
        if ($j.Arguments) { $execArgs += " $($j.Arguments)" }

        $serviceUnit = @"
[Unit]
Description=NetGuard $($j.Name) - $($j.Description)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$pwshPath $execArgs
WorkingDirectory=$NGRoot
# Least privilege: only the download watcher handles attacker-supplied files,
# and it runs as the unprivileged user rather than root.
User=$(if ($j.RunAs -eq 'SYSTEM') { 'root' } else { $UserPrincipal })
NoNewPrivileges=$(if ($j.RunAs -eq 'SYSTEM') { 'no' } else { 'yes' })
PrivateTmp=yes
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=$NGRoot
"@
        if ($j.LongRunning) {
            $serviceUnit = $serviceUnit -replace 'Type=oneshot', "Type=simple`nRestart=always`nRestartSec=30"
        }

        $onCalendar = switch ($j.Schedule) {
            'interval' { "*:0/$($j.IntervalMinutes)" }
            'daily' { "*-*-* $($j.At):00" }
            'weekly' { "$($j.DayOfWeek.Substring(0,3)) *-*-* $($j.At):00" }
            'logon' { $null }
        }

        Set-Content -LiteralPath "$unitDir/$unitName.service" -Value $serviceUnit -Encoding utf8

        if ($onCalendar) {
            $timerUnit = @"
[Unit]
Description=NetGuard $($j.Name) timer

[Timer]
OnCalendar=$onCalendar
# Persistent catches up a run missed while the machine was off - otherwise a
# laptop that sleeps through 03:15 simply never runs the daily audit.
Persistent=true
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
"@
            Set-Content -LiteralPath "$unitDir/$unitName.timer" -Value $timerUnit -Encoding utf8
            Invoke-NGCommand -FilePath 'systemctl' -Arguments @('enable', '--now', "$unitName.timer") | Out-Null
        }
        else {
            Invoke-NGCommand -FilePath 'systemctl' -Arguments @('enable', '--now', "$unitName.service") | Out-Null
        }
        $registered += $j.Name
    }
    Invoke-NGCommand -FilePath 'systemctl' -Arguments @('daemon-reload') | Out-Null
    $registered
}

function Unregister-NGSchedule {
    $removed = @()
    foreach ($f in (Get-ChildItem '/etc/systemd/system' -Filter 'netguard-*' -File -ErrorAction SilentlyContinue)) {
        Invoke-NGCommand -FilePath 'systemctl' -Arguments @('disable', '--now', $f.Name) | Out-Null
        Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
        $removed += $f.Name
    }
    Invoke-NGCommand -FilePath 'systemctl' -Arguments @('daemon-reload') | Out-Null
    $removed
}

function Get-NGScheduleStatus {
    $out = @()
    $list = Invoke-NGCommand -FilePath 'systemctl' -Arguments @('list-timers', 'netguard-*', '--all', '--no-pager', '--no-legend')
    if ($list.ok) {
        foreach ($line in ($list.stdout -split "`n")) {
            if (-not $line.Trim()) { continue }
            $cols = $line -split '\s{2,}'
            $out += [pscustomobject]@{
                name = ($cols | Select-Object -Last 1)
                state = 'timer'
                nextRun = $cols[0]
                lastRun = $(if ($cols.Count -ge 4) { $cols[3] } else { $null })
                lastResult = $null
            }
        }
    }
    $out
}

Export-ModuleMember -Function *
