# Contributing to NetGuard

Thanks for looking. This file covers the things that are specific to this
project; the usual fork/branch/PR mechanics apply as normal.

## Before you write code

Run the self-test. It is the fastest way to learn whether your environment is
sane and whether you broke something.

```powershell
./Test-NetGuard.ps1
```

It should report `FAIL 0`. `WARN` items are unconfigured optional features
(Discord, SMTP, VirusTotal) or checks that need elevation.

## The rule that governs everything

**Rules decide. AI explains.**

Detection is deterministic. The AI layer adds context, reviews script source,
and writes the weekly narrative. It is never in the path that decides whether
to alert.

A pull request that makes an alert conditional on a model response will be
rejected. Concretely:

- the model may **raise** a severity; it may never lower one below the
  rule-based floor
- the model runs with `--tools ""`, a replaced system prompt, and a JSON schema
- untrusted evidence goes through `Format-NGEvidence`, which strips the fence
  marker from the payload first
- if the AI layer is unavailable, every code path must still produce findings

## Failure modes we care about most

A monitoring tool fails dangerously when it goes quiet. Two things follow:

**Never let an error silence a check.** Do not wrap a collector in a bare
`try { } catch { }` that returns nothing. If a stage fails, emit an
`Availability` finding so the gap is visible. `Invoke-NGStage` in
`agents/_Bootstrap.ps1` does this for you.

**Never report unknown as good.** Use the tri-state pattern: `$true` means
confirmed enabled, `$false` means confirmed disabled, `$null` means could not
read. Detectors must test `-eq $false`, not `-not $x`, or unreadable data
becomes a false alarm — and, worse, a *readable* problem becomes invisible when
the surrounding block dies.

Two PowerShell traps that have already bitten this codebase and will bite you:

```powershell
@($null).Count        # 1, not 0  -> use Get-NGCount
[int]4294967295       # throws; under SilentlyContinue it abandons the whole
                      # enclosing assignment  -> use Get-NGSafeInt
$true -eq 'skip'      # True; the LEFT operand drives coercion
foreach ($a in ...)   # clobbers an outer $A - variables are case-insensitive
```

## Adding a detection

Detections live in `lib/NetGuard.Detect.psm1` (cross-platform) or in a
provider's `Find-NGPlatformPostureFindings` (OS-specific).

Every finding must carry:

- a **title** naming the mechanism, not the category. "svchost reaching a
  3-day-old domain on 443 with no parent browser process" beats "suspicious
  network activity".
- a **recommendation** someone can actually execute.
- a **`FingerprintSeed`** that is stable across runs for the same underlying
  condition but distinct for genuinely different events. Get this wrong and you
  either spam the channel or collapse separate incidents into one.

Then prove it does not add noise:

```powershell
./agents/Invoke-SentinelAgent.ps1 -NoAlert -NoAI   # run 1: learns baselines
./agents/Invoke-SentinelAgent.ps1 -NoAlert -NoAI   # run 2: this is the noise floor
```

Run 2 should be close to empty on a healthy machine. The reference figure on the
development host is **5 findings per cycle, all genuine**. If your change pushes
that up, it needs a baseline, a cooldown, or tighter logic. Noise is not a
cosmetic problem — it is how a monitoring system gets muted and stops mattering.

## Adding or changing a hardening control

Controls are data, not code. Add a row to the provider's `Get-NGHardeningChecks`
with all of: `Id`, `Tier`, `Weight`, `Category`, `Title`, `Rationale`, `Risk`,
`Test`, `Apply`, `Rollback`.

- **`Test`** returns `$true` when already compliant. If it throws, the engine
  records `error` — never `pass`. An unknown control must not inflate the score.
- **`Rollback` is mandatory** and must actually reverse `Apply`. The two
  exceptions in the tree (`CRED-WDIGEST`, `PRIV-INSTALLER`) deliberately refuse
  to reverse, because doing so would reintroduce a known weakness; they print a
  note instead. Follow that pattern rather than shipping an empty rollback.
- **`Risk` must be honest.** "Moderate. Older NAS units and printers that do not
  support signing will stop connecting" is useful. "Low risk" is not.
- **Tiering:** 1 = no expected user impact, 2 = may break legacy devices or
  older software, 3 = enterprise-grade, ships in audit mode first.

Generated scripts are emitted verbatim with no added indentation. Do not
"tidy" that — indenting a line puts whitespace before a here-string terminator
(`"@`), which is a parse error. There is a test for this.

## Adding a platform provider

See `docs/PROVIDERS.md`. In short: implement the contract in
`providers/<name>/Provider.psm1`, emit the normalised shapes so the shared
detectors work unchanged, and put OS-specific rules in
`Find-NGPlatformPostureFindings`. The shared layer must not gain an
`if ($IsLinux)`.

## Pull request checklist

- [ ] `./Test-NetGuard.ps1` reports `FAIL 0`
- [ ] Steady-state noise did not increase (run an agent twice, compare)
- [ ] New collectors degrade to a finding on failure, never to silence
- [ ] Unknown state is `$null` and does not alert
- [ ] No secret, webhook, token or hostname in code, logs, tests or fixtures
- [ ] New hardening controls have a working `Rollback`
- [ ] Cross-platform code has no OS branch outside a provider
- [ ] PowerShell 5.1 compatible in shared code (no `??`, no ternary, no `&&`)

That last one is not stylistic: Windows ships 5.1 and many users will never
install 7. Provider code under `providers/linux/` may assume 7.

## Testing the Linux provider from Windows

WSL is enough and does not need a VM:

```powershell
wsl -d Ubuntu -- pwsh -File /mnt/c/NetGuard/Test-NetGuard.ps1
```

## Reporting security defects

Do not open a public issue. See [SECURITY.md](SECURITY.md).
