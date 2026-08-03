# Project State

_Last updated: 2026-08-03_

## Current status
Multi-source investigation workflow is fully wired end-to-end and exercised
against a synthetic sample dataset. Threat-intel ingestion workflow produced its
first report.

## Artifacts produced

| Path | Status | Notes |
| --- | --- | --- |
| `analysis/ti-2026-08-03-bumblebee-adaptixc2-akira.md` | Done | TI ingest of DFIR Report (BumbleBee→AdaptixC2→Akira) + Atomic Red Team sim plan |
| `.claude/agents/endpoint-analyst.md` | Done | Endpoint subagent (Read, Bash) |
| `.claude/agents/cloud-analyst.md` | Done | Cloud subagent (Read, Bash) |
| `logs/windows/security.json`, `logs/windows/sysmon.json` | Done | Synthetic endpoint sample data |
| `logs/cloud/azuread_signin.json`, `logs/cloud/azuread_audit.json` | Done | Synthetic cloud sample data |
| `logs/README.md` | Done | Scenario + correlation map for sample data |
| `analysis/endpoint.md` | Done | Endpoint analysis notes |
| `analysis/cloud.md` | Done | Cloud analysis notes |
| `analysis/correlation.md` | Done | Unified endpoint↔cloud correlation |

## Sample-data scenario (synthetic)
Tenant/domain **contoso.com**, 2025-07-15 → 07-17 UTC. IT admin `jsmith` runs a
trojanized OpManager MSI → DLL side-load (BumbleBee) → AdaptixC2 → `backup_EA`
domain-admin abuse → NTDS/Veeam/LSASS theft → reverse-SSH + SFTP exfil → Akira on
`BKP01`. On-prem creds pivot into Entra ID: Global Admin elevation, rogue service
principal, MFA/Security Defaults teardown.

Attacker IPs bridging both planes: `172.96.137.160` (AdaptixC2), `185.174.100.203`
(Kyiv/exfil), `193.242.184.150` (reverse-SSH). Shared accounts: `jsmith`,
`backup_EA`/`backup_ea`, `itadmin` (cloud-only).

## Known open items / caveats
- `defuddle` and `npx` are NOT installed on this host — TI ingest fell back to `WebFetch`.
- `endpoint-analyst` subagent aborted once on an automated cyber-safeguard false
  positive; that analysis was completed inline. Cloud subagent ran cleanly.
- Correlation flagged an unresolved point: the 02:11 cloud sign-in PRECEDES the
  on-prem NTDS dump (~7h), so that credential likely came from the earlier
  AdaptixC2 foothold/token theft, not NTDS — unconfirmed.

## Suggested next steps
- Package the analysis set into a single incident report (Word/PDF) if a formal deliverable is needed.
- Consider a `/correlate` slash command to automate the endpoint+cloud fan-out and merge.
- Pull the gap-filling logs listed in `analysis/correlation.md` §6 to resolve the open items.
