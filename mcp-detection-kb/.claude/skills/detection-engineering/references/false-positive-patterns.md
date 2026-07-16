# False Positive Patterns

SKILL.md requirement 3 requires `falsepositives` to list concrete legitimate
activity, not a bare "Unknown". This reference catalogs common FP sources by
category so you don't have to rediscover them for every new rule. Use it as
a checklist when drafting the `falsepositives` field, and adapt entries to
the specific technique the rule targets.

## Administration & IT tooling

- Legitimate use of remote administration tools (PsExec, PDQ Deploy, SCCM,
  Intune remote actions) by IT staff
- Help-desk or admin use of built-in Windows remote management (WinRM,
  WMI, `Enter-PSSession`) for routine support
- Scripted bulk account/permission changes run by IAM/identity teams
- Domain controller replication and maintenance tasks (can resemble
  DCSync-adjacent activity)

## Security & monitoring tooling

- EDR/AV agents that legitimately read process memory, hook APIs, or touch
  LSASS for their own detection logic (e.g. Defender for Endpoint, CrowdStrike,
  SentinelOne) — usually excludable via a process-name/path allowlist
- Vulnerability scanners (Nessus, Qualys, Rapid7) generating traffic that
  resembles exploitation attempts or authentication brute-forcing
- SIEM/log-forwarding agents creating new scheduled tasks or services during
  install/update
- Backup agents (Veeam, Commvault, Windows Server Backup) that read
  registry hives, VSS snapshots, or file contents broadly

## Software installation & updates

- Software installers/updaters (e.g. Windows Update, Chocolatey, winget)
  that create services, modify registry run keys, or drop files in system
  directories
- Package managers unpacking archives to paths that resemble staging
  directories used by malware

## Developer & automation workflows

- CI/CD runners or service accounts performing bulk API calls, authentication,
  or file operations that look like scripted/automated activity
- Legacy or third-party applications forced onto older auth flows (e.g.
  ROPC, Basic Auth) because they cannot be updated to modern flows
- Test/staging environments deliberately exercising attack-adjacent behavior
  (red team tooling, purple team exercises, DAST scanners)

## Native OS / built-in behavior

- Windows Error Reporting (WerFault.exe) generating crash dumps of
  processes, including sensitive ones like lsass.exe, after a crash
- Task Manager "Create dump file" used by an administrator for legitimate
  troubleshooting
- Group Policy or MDM-driven configuration changes that resemble
  registry/persistence tampering
- Certificate auto-enrollment or scheduled maintenance tasks that create or
  modify scheduled tasks on a recurring basis

## Cloud / identity provider specifics

- Conditional Access policy testing or "what-if" evaluations performed by
  identity administrators
- Service principals/managed identities performing high-volume automated
  sign-ins that resemble impossible-travel or velocity anomalies
- Break-glass/emergency access accounts used during legitimate outages
- Cross-tenant or guest-user sign-ins for approved B2B collaboration

## How to document these well

For each false-positive entry:

1. **Name the specific tool, role, or workflow**, not just "admin activity"
   (e.g. "Veeam Backup & Replication agent" not "backup software" alone, if
   you know which product is in scope).
2. **State why it triggers the rule** if not obvious, so a future reviewer
   can tell whether the FP condition still applies after the detection logic
   changes.
3. **Prefer adding a filter over just documenting** when the FP source is
   identifiable by process name/path/account — see `filter_known_edr` in
   `example-rules/lsass_memory_access.yml` for the pattern. Document in
   `falsepositives` even when you've also added a filter, since filters can
   be incomplete or environment-specific.
4. If truly nothing is known to cause false positives, say so explicitly
   with reasoning (e.g. "None known — technique has no legitimate use in
   this environment") rather than leaving the field blank.
