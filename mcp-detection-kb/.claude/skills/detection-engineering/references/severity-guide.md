# Severity Guide

`level` must be exactly one of `low`, `medium`, `high`, `critical` (see
SKILL.md requirement 2). This guide gives concrete criteria for choosing
between them, plus the justification each level requires.

Severity is a function of two things: **impact** (what happens if the
detected activity is a true positive and goes unaddressed) and
**confidence** (how likely the matched pattern is to be malicious rather
than benign). A high-impact technique with a noisy, low-confidence query
should usually be scored lower than the raw impact would suggest, and vice
versa.

## critical

Use when a true positive means **imminent or in-progress high-impact
compromise** with very high confidence — the kind of alert that justifies
waking someone up.

Typical triggers:
- Confirmed ransomware behavior (mass file encryption, shadow copy deletion
  immediately followed by encryption-pattern file writes)
- Domain Admin / Enterprise Admin account creation or use from an unexpected
  source
- Active data exfiltration at volume from a sensitive data store
- Malware execution matching a known APT toolset with no legitimate use

Justification example:
> Severity is critical because this pattern (vssadmin delete shadows
> followed by mass .locked file writes) has no legitimate business
> justification and directly precedes irreversible data loss.

## high

Use when a true positive gives an attacker **significant capability or
access** (credential material, code execution, persistence, lateral
movement primitive) and the detection pattern has **low benign-usage
rate**.

Typical triggers:
- Credential dumping (LSASS access, SAM/NTDS hive export, DCSync)
- Exploitation of a public-facing service
- New scheduled task/service created by an unusual parent process
- Disabling of security tooling (EDR, AV, logging)

Justification example:
> Severity is high because a successful LSASS dump exposes plaintext
> credentials and Kerberos tickets for every logged-on account, and this
> access pattern has very low legitimate prevalence outside approved
> diagnostics tooling.

## medium

Use for activity that is **suspicious and worth investigating but not
independently conclusive** — often a building block of an attack chain, a
misuse of a legitimate feature, or something with a real (if smaller)
population of benign occurrences.

Typical triggers:
- Use of a legacy/weaker authentication flow (e.g. ROPC)
- PowerShell with obfuscation indicators but no confirmed malicious payload
- Unusual but not impossible login geography/time
- Reconnaissance commands (whoami, net user, ipconfig) run interactively by
  an unexpected process

Justification example:
> Severity is medium because ROPC exposes raw user credentials to the
> requesting application, but the flow is sometimes required by legacy
> line-of-business apps, so this alone is not conclusive of compromise.

## low

Use for activity that is **informational or a weak signal on its own** —
useful for context, hunting, or correlation, but not something that should
page anyone by itself.

Typical triggers:
- Policy-violation-but-not-security-relevant events (e.g. use of a
  disallowed but non-malicious tool)
- Baseline-establishing events (first-seen process/user/host combinations)
- Successful use of a sanctioned admin tool outside business hours, with no
  other suspicious indicators

Justification example:
> Severity is low because this event only indicates the first observed use
> of PsExec by this host; PsExec is widely used by IT and this alone does
> not indicate misuse.

## Choosing between adjacent levels

If you're torn between two levels, ask:

1. **Could this alert alone justify an incident response action (isolate
   host, disable account)?** If yes on its own, it's high or critical.
2. **Does the query have meaningful false-positive volume in a typical
   environment?** High FP volume pulls the severity down a level even if
   raw impact is high — pair it with tighter filtering instead of just
   lowering severity where possible.
3. **Is impact reversible/limited in scope (single host, single
   low-privilege account) or broad (domain-wide, data-store-wide)?**
   Broader blast radius pushes toward high/critical.

Never use severity levels outside the four allowed values (no
`informational`, `medium-high`, `critical-high`, etc.), and never leave
`level` without a justification somewhere in the rule — see SKILL.md
requirement 2.
