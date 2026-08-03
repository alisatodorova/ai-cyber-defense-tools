# Sample incident logs (synthetic)

Fabricated data for exercising the multi-source investigation workflow
(`endpoint-analyst` + `cloud-analyst`). **Not real telemetry.** Modeled on the
BumbleBee → AdaptixC2 → Akira campaign
(`analysis/ti-2026-08-03-bumblebee-adaptixc2-akira.md`).

## Files
| Path | Source | Format |
| --- | --- | --- |
| `windows/security.json` | Windows Security events | JSON array of event objects |
| `windows/sysmon.json` | Sysmon events | JSON array of event objects |
| `cloud/azuread_signin.json` | Azure AD sign-in logs | JSON array (Graph-like schema) |
| `cloud/azuread_audit.json` | Azure AD audit logs | JSON array (Graph-like schema) |

## Scenario
Tenant/domain: **contoso.com**. IT admin `jsmith` runs a trojanized
`ManageEngine-OpManager.msi` on `WS-IT-07`, leading to DLL side-loading
(BumbleBee), AdaptixC2, domain-admin abuse (`backup_EA`), NTDS/Veeam/LSASS
credential theft, RDP + reverse-SSH lateral movement, SFTP exfiltration, and
Akira ransomware on `BKP01`. On-prem credential theft pivots into **Entra ID /
Azure AD**: Global Admin elevation, rogue service principal, MFA/CA teardown.

Timeline: 2025-07-15 → 2025-07-17 (UTC).

## Built-in correlation points (endpoint ↔ cloud)
| Pivot | Endpoint | Cloud |
| --- | --- | --- |
| IP `172.96.137.160` | AdaptixC2 beacon (sysmon) | `jsmith` sign-in 14:33 |
| IP `185.174.100.203` | FileZilla SFTP exfil | `jsmith`/`itadmin` sign-ins from Kyiv |
| IP `193.242.184.150` | reverse SSH tunnel | `backup_ea` sign-in |
| User `jsmith` | initial workstation compromise | risky cloud sign-ins + GA elevation |
| Account `backup_EA` | created on DC (4720/4728) | synced acct signs into cloud |
| Time `2025-07-16 ~02:11` | NTDS.dit dumped ~09:21 prior day | creds reused for cloud sign-in |
