## What this changes

<!-- One or two sentences. -->

## Why

<!-- What problem does it solve? For a new detection, what does an attacker do
     that this catches? -->

---

## Checklist

- [ ] `pwsh -File Test-NetGuard.ps1` reports **FAIL 0**
- [ ] Tested on both platforms, or the change is provider-scoped to one
- [ ] No secret, webhook, token, hostname or IP in code, tests or fixtures

### If this touches detection

- [ ] Ran an agent **twice** and compared: steady-state noise did not increase
- [ ] New findings name the *mechanism*, not the category
- [ ] `FingerprintSeed` is stable for the same condition and distinct for new ones
- [ ] Log rules match on structure (syslog identifier, event ID), never free text

Noise is not cosmetic. The reference floor is 5 findings per cycle on a healthy
host; a change that raises it needs a baseline, a cooldown, or tighter logic.

### If this touches a hardening control

- [ ] `Rollback` exists and actually reverses `Apply`
- [ ] `Risk` is honest about what breaks — "low risk" is not an answer
- [ ] `Test` returns `$true` only when genuinely compliant, and throws rather
      than returning `$true` when it cannot tell
- [ ] Tier is right: 1 = no user impact, 2 = may break legacy software,
      3 = enterprise-grade, ships in audit mode

### If this touches shared code

- [ ] No OS branch outside `providers/`
- [ ] PowerShell 5.1 compatible (no `??`, no ternary, no `&&`)
- [ ] Unknown state is `$null` and stays silent; `$false` still alerts
- [ ] Counts go through `Get-NGCount`, integer casts through `Get-NGSafeInt`
- [ ] No module imports another module — load order belongs to `Import-NGStack`

## Anything reviewers should look at closely

<!-- Be specific. "The regex in Get-NGSecurityEvents" beats "the changes". -->
