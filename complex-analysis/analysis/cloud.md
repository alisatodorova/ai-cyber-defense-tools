# Cloud Analysis — Azure AD Sign-in + Audit

**Source:** `logs/cloud/azuread_signin.json` (6 sign-ins), `logs/cloud/azuread_audit.json` (7 audit events)
**Tenant:** contoso.com | **Timezone:** UTC

Narrative: an on-prem endpoint compromise pivots into the cloud tenant. `jsmith` is compromised,
elevated to Global Admin, MFA/security controls are disabled, a rogue service principal is planted
for persistence, and attacker-created account `backup_ea` is synced and added to a privileged group.

## Timeline (UTC)

| Time | Source | Actor | Event | IP / Location | Notes |
| --- | --- | --- | --- | --- | --- |
| 07-15 08:31:44 | Sign-in | jsmith@contoso.com | Success — Exchange Online (Edge/Win10) | 203.0.113.10 / Seattle US | Baseline normal corp sign-in |
| 07-15 14:33:52 | Sign-in | jsmith@contoso.com | Success — Azure PowerShell (desktop) | 172.96.137.160 / Buffalo US | risk=medium, unfamiliarFeatures; AdaptixC2 hosting IP |
| 07-16 02:11:07 | Sign-in | jsmith@contoso.com | Failure 50126 — Graph CLI (Linux/python) | 185.174.100.203 / Kyiv UA | risk=high; failed guess from exfil IP |
| 07-16 02:11:39 | Sign-in | jsmith@contoso.com | Success (single-factor) — Graph CLI | 185.174.100.203 / Kyiv UA | 32s after failure; adminConfirmedSigninCompromised |
| 07-16 02:18:55 | Sign-in | itadmin@contoso.com | Success — AAD PowerShell (Linux/python) | 185.174.100.203 / Kyiv UA | Break-glass admin from same attacker IP |
| 07-16 02:22:31 | Audit | itadmin@contoso.com | Add member to role → jsmith = Global Administrator | 185.174.100.203 | Privilege escalation |
| 07-16 02:29:48 | Audit | itadmin@contoso.com | Add service principal `backup-sync-connector` | 185.174.100.203 | SP persistence |
| 07-16 02:31:12 | Audit | itadmin@contoso.com | Add app role to SP → Directory.ReadWrite.All, Mail.Read | 185.174.100.203 | High-priv Graph perms |
| 07-16 02:34:57 | Audit | itadmin@contoso.com | Add password/credential to SP | 185.174.100.203 | Client secret backdoor |
| 07-16 02:41:20 | Audit | jsmith@contoso.com | Update CA policy "Require MFA for admins" enabled→disabled | 185.174.100.203 | Defense evasion |
| 07-16 02:48:03 | Audit | jsmith@contoso.com | Disable Security Defaults | 185.174.100.203 | Defense evasion |
| 07-16 03:02:19 | Audit | jsmith@contoso.com | Add member to group "Global Admins" → backup_ea@contoso.com | 185.174.100.203 | Account persistence |
| 07-16 09:14:02 | Sign-in | backup_ea@contoso.com | Success — Graph CLI (Linux/python) | 193.242.184.150 / Amsterdam NL | risk=high; reverse-SSH tunnel IP |

## IOCs

| Type | Value | Context |
| --- | --- | --- |
| IP | 203.0.113.10 | jsmith baseline (Seattle) — known-good |
| IP | 172.96.137.160 | Buffalo; AdaptixC2 hosting IP; first anomalous sign-in (risk medium) |
| IP | 185.174.100.203 | Kyiv, UA; primary attacker/exfil IP — all failed+successful compromise sign-ins and every audit change |
| IP | 193.242.184.150 | Amsterdam, NL; reverse-SSH tunnel IP used by backup_ea |
| Username | jsmith@contoso.com | Compromised user, elevated to Global Admin |
| Username | itadmin@contoso.com | Break-glass Global Admin, credential harvested on-prem |
| Username | backup_ea@contoso.com | Attacker-created on-prem account, synced to cloud |
| App/SP | backup-sync-connector, appId b1e7c3a0-9f21-4a55-8c14-77de0c2f9a10 | Rogue service principal for persistence |
| App | Microsoft Graph Command Line Tools / Azure AD PowerShell | Abused first-party clients |
| User agent | python-requests/2.31.0 (Linux) | Scripted attacker tooling across all UA-Linux sign-ins |
| Tenant | contoso.com | Target tenant |
| Group | "Global Admins" | Privileged group backdoored |
| Policy | "CA01 - Require MFA for admins", "Security Defaults" | Disabled controls |

## ATT&CK Techniques

| Technique | ID | Evidence (activity + timestamp) | Confidence |
| --- | --- | --- | --- |
| Valid Accounts: Cloud Accounts | T1078.004 | jsmith success 02:11:39; itadmin 02:18:55; backup_ea 09:14:02 | High |
| Brute Force | T1110 | Failure 50126 @02:11:07 → success @02:11:39 (same IP/UA) | Medium |
| OS Credential Dumping (upstream) | T1003 | password/token reuse; singleFactor success implies stolen credential/token | Medium |
| Account Manipulation: Additional Cloud Roles | T1098.003 | Add member to role → jsmith Global Admin @02:22:31 | High |
| Account Manipulation: Additional Cloud Credentials | T1098.001 | Add password to SP @02:34:57; app role @02:31:12 | High |
| Create Account: Cloud Account | T1136.003 | backup_ea → "Global Admins" @03:02:19; sign-in @09:14:02 | High |
| Impair Defenses | T1562.001 / T1562.007 | CA "Require MFA" disabled @02:41:20; Security Defaults disabled @02:48:03 | High |
| Modify Authentication Process (MFA) | T1556.006 | MFA/Security Defaults disablement; single-factor success | High |
| Impossible Travel (behavioral → T1078.004) | — | Buffalo US 14:33 → Kyiv UA 02:11; risk=high | High |
| Email/Data collection via SP | T1114 (potential) | SP granted Mail.Read + Directory.ReadWrite.All @02:31:12 | Medium |
| Token replay | T1550.001 | 02:11:39 success flagged compromised, single-factor despite MFA policy | Medium |

## Key anomalies

- Impossible travel (High): Buffalo NY 07-15 14:33 → Kyiv UA 07-16 02:11.
- Failed→success (High): 32s gap, identical IP/UA (185.174.100.203, python-requests) — automated cred validation.
- Multiple OS/UA per user (High): jsmith Windows/Edge + Windows/AzPowerShell, then Linux/python; itadmin & backup_ea only ever Linux/python.
- Single-factor success while MFA-for-admins CA still enabled (disabled later @02:41) — account not MFA-gated or token bypass.
- Privilege chain in ~40 min (High): role elevation → rogue SP → Graph perms → SP secret → CA disable → Security Defaults disable → backup_ea into Global Admins, one IP, 02:22–03:02.

## Correlation Hints (for endpoint / Windows + Sysmon)

- Shared IPs: 172.96.137.160 (AdaptixC2 — endpoint Sysmon 3 before 07-15 14:33); 185.174.100.203 (exfil, 07-16 02:00–03:00); 193.242.184.150 (reverse-SSH endpoint).
- Usernames to join: jsmith, itadmin, backup_ea. Look on-prem for NTDS/LSASS dumping before 02:11, backup_ea account creation (4720), itadmin credential use before 02:18:55.
- Timestamp alignment: endpoint C2 precedes 07-15 14:33; credential dump/lateral movement clusters near 07-16 02:11.
- Tooling signature: python-requests/2.31.0 Linux — attacker infra, not managed corp endpoints.
- Hunt forward: rogue SP backup-sync-connector (b1e7c3a0…9a10) will auth non-interactively even after user remediation — monitor SP sign-ins by that appId.

## Analyst caveat
Several conclusions are reinforced by embedded `note` fields in the sample data (treated as analyst
annotations, not independently observed telemetry) — hence upstream credential-dumping is rated Medium
pending the endpoint logs.
