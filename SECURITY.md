# Security Policy

NetGuard is a security tool, so a defect in it can quietly remove protection
rather than visibly break something. Please treat that seriously — and so will we.

## Reporting a vulnerability

**Do not open a public issue for a security defect.**

Use GitHub's private reporting: **Security → Report a vulnerability** on this
repository. If that is unavailable, open an issue titled `security contact
request` with no technical detail and a maintainer will arrange a private channel.

Please include:

- what an attacker gains, in one sentence
- the affected file and function
- the platform and provider (`windows` / `linux`), OS version, PowerShell version
- reproduction steps, or a minimal proof of concept
- whether it is already public

We aim to acknowledge within 72 hours and to ship a fix or a documented
mitigation within 30 days for anything rated High or Critical. We will credit
you in the advisory unless you ask us not to.

## What counts as a vulnerability here

The severe class for this project is **silent loss of detection**. A bug that
makes NetGuard report "nothing to report" when something *was* wrong is worse
than a crash, because the absence of alerts is indistinguishable from safety.

In scope, roughly in order of severity:

- **Detection suppression.** Any input that causes a collector or detector to
  silently skip, return empty, or drop a finding. Real examples already fixed:
  a Defender field that failed an `[int]` cast and, under
  `$ErrorActionPreference = 'SilentlyContinue'`, abandoned the entire
  antivirus-health block; a baseline serialisation bug that made every item
  look new forever.
- **Prompt injection that changes an outcome.** The AI layer reads
  attacker-controlled text (filenames, command lines, script bodies). It runs
  with no tools and cannot lower a rule-based severity by design. A way around
  either property is a vulnerability.
- **Secret exposure.** Anything that writes the secret store, its entropy key,
  a webhook URL, an SMTP password or an API token to a log, a report, a
  console, a commit, or a notification body.
- **Privilege escalation via NetGuard.** The agents run as SYSTEM (Windows) or
  root (Linux). Any path where an unprivileged user influences what they
  execute — writable script paths, unquoted paths, injectable arguments,
  insecure temp files, symlink attacks on the install tree.
- **Quarantine escape.** Anything that lets a quarantined file execute, or that
  tricks the scanner into quarantining an arbitrary path.
- **Remote deployment abuse.** Anything in `remote/` that could be used to push
  code to hosts other than the intended targets.

## Out of scope

- Findings NetGuard does not detect. Missing coverage is a feature request, not
  a vulnerability. Open a normal issue.
- False positives, unless they can be induced remotely to drown out real alerts.
- Weaknesses that require you to already be an administrator on the monitored
  host, *unless* they defeat a control NetGuard explicitly claims to provide.
- Findings in Windows, systemd, Defender, ClamAV or the Claude CLI themselves —
  report those upstream.

## Design decisions that look like bugs

These are deliberate. Reporting them is fine, but we will likely close as
`by-design` with a pointer here.

- **Secrets are decryptable by any Administrator/root on the same host.** On
  Windows the blob is DPAPI at `LocalMachine` scope, because the agents run as
  SYSTEM and could not read a `CurrentUser` blob. On Linux it is AES with a
  root-owned `0600` key file. In both cases the file ACL is the control, not
  the cipher. If an attacker is already SYSTEM or root, the secret store is not
  your remaining problem.
- **Hardening scripts are generated, never auto-applied.** A background process
  that silently reconfigures security settings is indistinguishable from
  malware, and an automated change that breaks a VPN at 3am is worse than the
  gap it closed.
- **VirusTotal lookups are hash-only by default.** Uploading a file publishes
  its contents to a third party permanently. Upload is opt-in.
- **Baselines trust the state at first run.** If the host is already
  compromised when you install NetGuard, the implant becomes part of the
  baseline. This is documented, not hidden — establish baselines on a machine
  you believe is clean.

## Supported versions

Security fixes land on `main` and in the most recent tagged release. There are
no long-term support branches.
