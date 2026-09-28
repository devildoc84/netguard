# NetGuard

Agent-based host and network monitoring for **Windows and Linux**, with
AI-assisted triage, download scanning, and audit-first hardening.

No agent fees, no cloud, no account. One PowerShell tree, two platform
providers, alerts to Discord and your phone.

```
Windows 10/11, Server 2016+     PowerShell 5.1 or 7
Linux (systemd distributions)   PowerShell 7
```

---

## The one design decision that matters

**Rules decide. AI explains.**

Detection is entirely deterministic. The AI layer adds context, reviews the
source of downloaded scripts, and writes the weekly narrative — but it is never
in the path that decides whether to alert.

1. **Availability.** If the model is unreachable, rate-limited or
   unauthenticated, detection keeps working. Only the commentary is lost.
2. **Prompt injection.** Everything fed to the model is attacker-controllable:
   filenames, command lines, DNS names, script bodies. A model that could
   *lower* a severity would be a control an attacker can talk their way past.
   The model may raise a severity; it can never lower one below the rule-based
   floor.
3. **Reproducibility.** The same input always produces the same alert.

The analyst runs with `--tools ""` (no filesystem, no shell, no network), a
replaced system prompt, and a JSON schema its output must validate against.
Evidence is fenced, and the fence marker is stripped from the payload first. If
the evidence contains text trying to instruct the model, that is itself reported
as a finding.

---

## What it watches

| Agent | Cadence | Runs as | Does |
|---|---|---|---|
| **Sentinel** | 15 min | SYSTEM / root | Log triage, new listeners, hosts-file tampering, agent liveness |
| **Discovery** | hourly | SYSTEM / root | LAN inventory, perimeter checks, autorun + account + root-cert drift |
| **Hardening** | daily 03:15 | SYSTEM / root | Posture audit, scoring, regenerates reversible fix scripts |
| **WeeklyReport** | Mon 08:00 | SYSTEM / root | HTML report + Discord summary + SMS digest |
| **DownloadWatcher** | at logon | **your user** | Scans files as they land in Downloads |

The watcher runs unprivileged *on purpose*. It parses attacker-supplied files
all day; running that as root would hand any parser bug the highest privilege on
the box. Least privilege matters most exactly where the untrusted input is.

---

## Install

```bash
git clone https://github.com/YOUR-USER/netguard.git
cd netguard
```

**Windows** (elevated PowerShell):

```powershell
.\Setup-NetGuard.ps1          # prompts for Discord webhook, SMS gateway, SMTP
.\Test-NetGuard.ps1           # must report FAIL 0
.\install\Register-Tasks.ps1
.\agents\Invoke-HardeningAgent.ps1
notepad .\harden\Apply-Tier1.ps1   # read it first
.\harden\Apply-Tier1.ps1
```

**Linux**:

```bash
sudo pwsh -File ./Setup-NetGuard.ps1
pwsh -File ./Test-NetGuard.ps1
sudo pwsh -File ./install/Register-Tasks.ps1
pwsh -File ./agents/Invoke-HardeningAgent.ps1
less ./harden/Apply-Tier1.ps1      # read it first
sudo pwsh -File ./harden/Apply-Tier1.ps1
```

PowerShell 7 on Linux: `https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux`

### Secrets

Encrypted at rest with a platform-appropriate cipher — DPAPI (LocalMachine) on
Windows, AES-256-CBC with an HMAC tag and a root-owned `0600` key file on Linux.

In both cases **the file permissions are the real control, not the cipher.** The
agents run as SYSTEM/root and must decrypt unattended, so anything they can read,
an attacker who is already SYSTEM/root can read too. If that is your situation,
the secret store is not your remaining problem.

Nothing is echoed to the console or written to a transcript.

---

## Hardening: audit first, you pull the trigger

The hardening agent **never applies a change.** It scores the host and writes
paired scripts:

```
harden/Apply-Tier1.ps1      harden/Rollback-Tier1.ps1
harden/Apply-Tier2.ps1      harden/Rollback-Tier2.ps1
harden/Apply-Tier3.ps1      harden/Rollback-Tier3.ps1
```

Every generated script takes a safety net first (a System Restore point on
Windows, a timestamped config backup on Linux), requires you to type `APPLY`,
and carries a per-control `WHY:` and `RISK:` comment.

| Tier | Windows | Linux |
|---|---|---|
| **1** safe | ASR rules, Network Protection, MAPS, firewall logging + explicit inbound block, PowerShell script-block logging, command-line auditing, log sizing, LLMNR off, AutoRun off | unattended security updates, default-deny firewall + logging, no root SSH, network + kernel sysctls, persistent journal, auditd with execve rules, umask 027, no core dumps |
| **2** moderate | Controlled Folder Access (audit), LSASS RunAsPPL, SMB signing, SMBv1 removal, NetBIOS off, stricter UAC | SSH keys-only, no passwordless sudo, ClamAV, noexec on /tmp and /dev/shm, fail2ban |
| **3** aggressive | Credential Guard, AppLocker (**audit only**), PowerShell v2 removal | AppArmor/SELinux (**complain/permissive first**), USBGuard, kernel module blacklist |

A control that used to pass and now fails raises a **score regression** alert on
its own. Something changed your configuration, and that is worth knowing
regardless of the control's own severity.

Two Windows controls are deliberately **not** reversible — rolling back WDigest
cleartext caching or `AlwaysInstallElevated` would reintroduce a known weakness.
They print a note instead.

Controls that do not apply to your host — SSH hardening on a machine with no SSH
daemon — are reported `n/a` and excluded from scoring, not counted as failures.

---

## Download scanning

Eight independent stages, scored deterministically:

1. **Identity** — SHA256, and type by *magic bytes* rather than extension
2. **Provenance** — Mark-of-the-Web including the originating URL (Windows)
3. **Signature** — Authenticode on Windows, package ownership on Linux
4. **Local AV** — Defender or ClamAV
5. **Reputation** — VirusTotal **hash lookup only**
6. **Static triage** — entropy, embedded URLs, LOLBins, macros, OOXML remote templates, double extensions, RTL-override filenames
7. **AI review** — source-level intent analysis for scripts and macros
8. **Verdict** — ≥60 quarantine, ≥25 suspicious, else allow

**VirusTotal sends only the hash.** Uploading a file publishes its contents to a
third party permanently, and for a personal machine that can mean leaking
documents. Upload is opt-in and off by default.

Quarantine renames the file so it cannot execute and moves it aside with a JSON
sidecar. **Nothing is ever deleted** — the file is the evidence of how it got in.

```powershell
pwsh -File scan/Scan-File.ps1 -Path ~/Downloads/setup.sh -Detailed
```

Stage 7 is where AI genuinely beats signatures: a novel downloader has no hash
reputation and may trip no signature, but its intent is plain in source.

---

## Alerting

Discord carries the detail; SMS carries the wake-you-up.

Three suppression layers, because an alerting system you mute is worse than none:

1. **Severity floor** per channel (Discord ≥ Medium, SMS ≥ Critical by default)
2. **Per-fingerprint cooldown** — the same finding does not page you hourly
3. **Hourly ceiling** — overflow collapses into one digest rather than vanishing

There is also a **dead-man's switch**. Every agent writes a heartbeat; Sentinel
alerts when one goes stale, and the weekly report carries an agent-health table.
A monitoring system that silently dies looks exactly like a quiet week.

---

## Architecture

```
lib/                      platform-neutral. No OS branches, ever.
  NetGuard.Platform.psm1    provider contract + Import-NGStack (the only loader)
  NetGuard.Core.psm1        config, secrets, state, logging, diffing
  NetGuard.Detect.psm1      cross-platform detection rules
  NetGuard.Harden.psm1      audit engine + script generator
  NetGuard.Scan.psm1        download pipeline
  NetGuard.Notify.psm1      Discord + SMS, routing and suppression
  NetGuard.AI.psm1          sandboxed model invocation

providers/<os>/           the only place allowed to know the OS
  Provider.psm1             collectors, crypto, scheduling
  Hardening.psm1            control catalogue + OS-specific rules
```

Providers fill a normalised posture contract, so the shared rules work
identically on both platforms. Adding an OS means adding a directory — see
[docs/PROVIDERS.md](docs/PROVIDERS.md). macOS is unimplemented and welcome.

**Modules never import each other.** `Import-NGStack` loads the graph in
dependency order, once. An `Import-Module -Force` from inside a module unloads
and reloads the shared graph mid-import, discarding module state and breaking
command resolution at runtime rather than at load time.

---

## Tuning

```powershell
pwsh -File tools/Approve-NGDevice.ps1                                   # what is on my network?
pwsh -File tools/Approve-NGDevice.ps1 -Mac AA:BB:CC:DD:EE:FF -Label TV
pwsh -File tools/Approve-NGDevice.ps1 -ApproveAll                       # at first install
```

First runs of Sentinel and Discovery **record baselines silently** rather than
alerting on the hundreds of autostart entries and root certificates that already
exist. Drift from that point forward is what alerts.

Measured steady-state noise floor on the development host: **5 findings per
cycle, all genuine.** If you see substantially more, something regressed — run
`Test-NetGuard.ps1` and `tests/Probe-Events.ps1`.

Edit `config/netguard.config.json` for severity floors, thresholds, watch paths
and retention.

---

## Known limits

- **Not EDR.** No kernel driver, no process-tree telemetry, no memory scanning.
  Add Sysmon (Windows) or auditd (Linux, and Tier 1 installs it) for real
  process visibility.
- **Polling, not streaming.** Sentinel runs every 15 minutes; its window
  overlaps to 20 to avoid boundary misses, but this is not real-time.
- **Baselines trust the starting state.** If the host is already compromised at
  first run, the implant becomes part of the baseline. Establish baselines on a
  machine you believe is clean, or after a rebuild.
- **Email-to-SMS is lossy.** Carriers throttle, truncate and silently drop, and
  several are retiring these gateways. It is the phone channel, not the record.
- **LAN discovery is ARP/ping-based.** A host that ignores ICMP and generates no
  ARP traffic is missed, and networks wider than a /22 are not swept
  host-by-host. It will not find devices on other VLANs.
- **macOS has no provider yet.** The seam exists; the implementation does not.
- **Linux `Get-NGSignatureStatus` reports package ownership**, not code signing,
  and marks itself `supported = $false` so unsigned binaries are not penalised
  the way they are on Windows.

---

## Troubleshooting

```powershell
pwsh -File Test-NetGuard.ps1            # any FAIL is a real defect
pwsh -File tests/Probe-Provider.ps1     # what each collector actually returns
pwsh -File tests/Probe-Events.ps1       # raw log lines behind each event rule
```

**Alerts stopped.** Check the agent-health table in the latest report, then
`state/heartbeat.json`.

**AI layer returns nothing.** If you run an agent from inside another Claude Code
session, inherited `CLAUDE_CODE_*` variables make the nested CLI hang waiting for
a host handshake it will never get. The AI module strips those for its child
process. For SYSTEM/root scheduled jobs you need a token from
`claude setup-token`, stored via the setup wizard.

**Too many alerts.** Raise `notify.discordMinSeverity`, or approve the devices
and autoruns causing them — rather than muting the channel.

---

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the failure modes this project cares
about, the PowerShell traps that have already bitten it, and how to add a
detection, a control, or a platform.

Security issues: [SECURITY.md](SECURITY.md). Please do not open a public issue.

## Licence

MIT — see [LICENSE](LICENSE).
