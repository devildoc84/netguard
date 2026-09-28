---
name: Bug report
about: Something behaves incorrectly
title: ''
labels: bug
assignees: ''
---

**Do not report security defects here.** See [SECURITY.md](../../SECURITY.md).

## What happened

<!-- One or two sentences. -->

## What you expected

## Severity, in this project's terms

- [ ] **Silent loss of detection** — NetGuard reported nothing when something was wrong
- [ ] False positive — NetGuard alerted on something benign
- [ ] Crash or error
- [ ] Cosmetic / documentation

Silent loss of detection is the worst class of bug here, because an absence of
alerts is indistinguishable from an absence of problems. Say so if that is what
you are seeing.

## Environment

```
Platform      :        # Windows 11 / Ubuntu 24.04 / ...
PowerShell    :        # $PSVersionTable.PSVersion
Provider      :        # from tests/Probe-Provider.ps1
Elevated      :        # yes / no
NetGuard rev  :        # git rev-parse --short HEAD
```

## Self-test output

```
# pwsh -File Test-NetGuard.ps1
# Paste the summary line and any FAIL rows.
```

## Reproduction

<!-- Exact commands. If it involves a detection, tests/Probe-Events.ps1 output
     showing the matched text is far more useful than a description of it. -->

## Logs

```
# Get-Content logs/netguard-*.jsonl -Tail 30
# Redact hostnames, IPs and anything else you would rather not publish.
```
