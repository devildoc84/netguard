# Writing a platform provider

A provider is the only place in NetGuard that is allowed to know what OS it is
running on. Everything above it — Core, Notify, AI, Detect, Harden, Scan and the
agents — is platform-neutral and must stay that way.

If shared code ever needs an `if ($IsLinux)`, that is a sign the contract is
missing a function. Add the function.

## Layout

```
providers/
  windows/
    Provider.psm1     collectors, crypto, scheduling
    Hardening.psm1    control catalogue + platform-specific posture rules
  linux/
    Provider.psm1
    Hardening.psm1
  macos/              <- your new provider goes here
    Provider.psm1
    Hardening.psm1
```

The directory name comes from `Get-NGProviderName` in
`lib/NetGuard.Platform.psm1`. `Import-NGProvider` loads `Provider.psm1` first,
then `Hardening.psm1`.

**Providers must not import other modules.** `Import-NGStack` loads the graph in
dependency order, exactly once. An `Import-Module -Force` from inside a module
unloads and reloads the shared graph mid-import: module-scoped state is silently
discarded and command resolution starts failing at runtime, not at load time.
This cost real debugging time — do not reintroduce it.

## The contract

`Test-NGProviderContract` verifies these exist. The self-test calls it, so a
missing function fails CI rather than a 3am scheduled run.

| Function | Returns |
|---|---|
| `Get-NGProviderInfo` | `{ name, displayName, osVersion, psVersion, capabilities[] }` |
| `Test-NGElevated` | `$true` when running as Administrator / root |
| `Get-NGHostPosture` | the normalised posture object (below) |
| `Get-NGListeningPorts` | `[{ protocol, localAddress, port, processId, processName, processPath, scope, loopbackOnly, reachable, key }]` |
| `Get-NGAutoruns` | `[{ type, location, name, command, key }]` |
| `Get-NGLocalAccounts` | `{ users[], adminMembers[], remoteUsers[] }` |
| `Get-NGTrustedCertificates` | `[{ store, subject, issuer, thumbprint, notBefore, notAfter, selfSigned, systemManaged, key }]` |
| `Get-NGHostsFileEntries` | `[{ entry, key }]` |
| `Get-NGSecurityEvents` | `{ windowMinutes, since, failedLogons[], logCleared[], accountChanges[], newServices[], newScheduledTasks[], avDetections[], suspiciousExecution[], remoteLogons[] }` |
| `Get-NGSignatureStatus` | `{ status, signer, issuer, thumbprint, notAfter, timeStamped, supported }` |
| `Invoke-NGAntivirusScan` | `{ ran, clean, engine, detail }` — `clean` is **tri-state** |
| `Get-NGHardeningChecks` | the control catalogue |
| `Get-NGRemediationPreamble` | text prepended to generated Apply scripts |
| `Protect-NGSecretBytes` / `Unprotect-NGSecretBytes` | `byte[]` |
| `Protect-NGFilePath` | restrict a file to admin/root; `$true` on success |
| `Find-NGPlatformPostureFindings` | findings the shared rules cannot express |

Optional, and degraded gracefully if absent:
`Register-NGSchedule`, `Unregister-NGSchedule`, `Get-NGScheduleStatus`,
`Get-NGLocalSubnet`, `Get-NGLanDevices`, `Reset-NGFilePathAcl`.

## The normalised posture

Start from `New-NGPosture` rather than building a hashtable. It returns every
field explicitly `$null`, so a field you forget reads as "unknown" instead of
being absent — the difference between a detector staying quiet and a detector
crashing on a missing property.

```
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
raw            { ...anything platform-specific... }
```

Fill the normalised fields and you inherit every cross-platform rule for free.
Put whatever else you collect in `raw`, and write rules against it in
`Find-NGPlatformPostureFindings`.

## Three rules that are not negotiable

**1. Tri-state, always.** `$true` = confirmed enabled, `$false` = confirmed
disabled, `$null` = could not read. Never substitute a default that reads as
healthy, and never one that reads as broken.

```powershell
$p.antivirus.realtimeEnabled = $false     # we checked; it is off      -> alerts
$p.antivirus.realtimeEnabled = $null      # we could not check         -> silent
```

The detectors test `-eq $false`, not `-not $x`. Getting this wrong in either
direction is a real bug: one floods the user with false criticals, the other
hides a genuinely disabled scanner.

**2. Never report "unknown" as "clean".** `Invoke-NGAntivirusScan` must return
`clean = $null` when the scan did not conclusively run. An early Windows build
treated any non-zero exit code as a detection, and quarantined every clean file
on the machine. Decide from the output text, and let anything unclassified stay
`$null`.

**3. Anchor log rules to structure, not free text.** Match on the syslog
identifier, the event ID, the provider name — never on a substring that could
appear anywhere in a log line. With free-text matching, anything that can write
to the log can forge a detection. During development, PowerShell source text
that landed in the journal produced a Critical "audit log was cleared" alert
three times over.

## Control catalogue

Controls are data. Each row needs `Id`, `Tier` (1–3), `Weight`, `Category`,
`Title`, `Rationale`, `Risk`, `Test`, `Apply`, `Rollback`, and optionally
`Applicable`.

```powershell
[pscustomobject]@{
    Id = 'MAC-GATEKEEPER'; Tier = 1; Weight = 9; Category = 'Application Control'
    Title     = 'Enable Gatekeeper'
    Rationale = 'Why this matters, in terms of what an attacker gains without it.'
    Risk      = 'Honest breakage warning. "Low risk" is not an answer.'
    Applicable = { $true }          # omit unless the control can be irrelevant
    Test      = { (spctl --status) -match 'assessments enabled' }
    Apply     = 'spctl --master-enable'
    Rollback  = 'spctl --master-disable'
}
```

- **`Test`** returns `$true` when already compliant. If it throws, the engine
  records `error` — never `pass`. An unevaluated control must not inflate the
  score.
- **`Applicable`** returning `$false` marks the control `n/a` and excludes it
  from scoring. Use it when the software simply is not installed: scoring a host
  down for not hardening an SSH daemon it does not run makes the score
  meaningless, and reporting it as `error` buries the controls that genuinely
  could not be evaluated.
- **`Rollback` is mandatory**, and there is a test that enforces it. If reversing
  a control would reintroduce a known weakness, print a note explaining that
  instead of silently doing nothing — see `WIN-WDIGEST` and `WIN-INSTALLER`.
- Generated scripts emit `Apply` and `Rollback` **verbatim, with no added
  indentation**. Indenting a line would put whitespace before a here-string
  terminator (`"@`), which is a parse error. There is a test for that too.

## Verifying your provider

```powershell
pwsh -File tests/Probe-Provider.ps1     # shows what every collector returns
pwsh -File tests/Probe-Events.ps1       # shows the raw lines behind each event rule
pwsh -File Test-NetGuard.ps1            # asserts; must report FAIL 0
```

`Probe-Events.ps1` is the one that catches embarrassing false positives. Run it
on an idle machine: every category should be empty. If something fires, look at
the matched text before assuming the rule is right.

Then check the noise floor, which matters more than any single detection:

```powershell
pwsh -File agents/Invoke-SentinelAgent.ps1 -NoAlert -NoAI   # run 1: learns baselines
pwsh -File agents/Invoke-SentinelAgent.ps1 -NoAlert -NoAI   # run 2: this is the real noise
```

Run 2 should be close to empty on a healthy host. The reference figure on the
development machine is **5 findings per cycle, all genuine**. A provider that
pushes that up needs baselines, cooldowns or tighter logic before it ships.
