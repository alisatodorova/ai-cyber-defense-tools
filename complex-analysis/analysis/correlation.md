# Correlation Analysis — Endpoint ↔ Cloud (Unified Picture)

**Sources:** `analysis/endpoint.md` (Windows Security + Sysmon), `analysis/cloud.md` (Azure AD sign-in + audit)
**Tenant/Domain:** contoso.com | **Timezone:** UTC
**Campaign:** BumbleBee → AdaptixC2 → Akira (double extortion), with parallel Entra ID takeover

## 1. Timeline Alignment (merged, UTC)

| Time | Plane | Event | Source |
| --- | --- | --- | --- |
| 07-15 08:31 | Cloud | jsmith baseline sign-in, Seattle (203.0.113.10) | cloud |
| 07-15 14:02 | Endpoint | jsmith runs trojanized MSI → DLL side-load (BumbleBee) on WS-IT-07 | endpoint |
| 07-15 14:05 | Endpoint | BumbleBee C2 → 188.40.187.145:443 | endpoint |
| 07-15 14:32 | Endpoint | AdaptixC2 beacon AdgNsy.exe → **172.96.137.160**:80 | endpoint |
| **07-15 14:33** | Cloud | **jsmith cloud sign-in from 172.96.137.160** (risk med) | cloud |
| 07-15 14:40 | Endpoint | Domain discovery (nltest, whoami) | endpoint |
| 07-15 18:44 | Endpoint | **backup_EA** created + Enterprise Admins on DC01 | endpoint |
| **07-16 02:11** | Cloud | jsmith failed→success from **185.174.100.203** (Kyiv), single-factor | cloud |
| 07-16 02:18–03:02 | Cloud | itadmin + jsmith: GA role, rogue SP + secret, MFA/Security Defaults off, backup_ea→Global Admins | cloud |
| 07-16 09:14 | Cloud | **backup_ea** cloud sign-in from **193.242.184.150** (Amsterdam) | cloud |
| 07-16 09:13–09:21 | Endpoint | backup_EA RDP to DC01 → **wbadmin NTDS.dit dump** | endpoint |
| 07-16 09:35 | Endpoint | LSASS dump via comsvcs.dll | endpoint |
| 07-16 16:47 | Endpoint | Veeam credential DB query on BKP01 | endpoint |
| 07-16 21:58 | Endpoint | Reverse SSH tunnel → **193.242.184.150** | endpoint |
| 07-16 23:41 | Endpoint | FileZilla SFTP exfil → **185.174.100.203** | endpoint |
| 07-17 03:22 | Endpoint | Akira locker.exe + shadow-copy deletion on BKP01 | endpoint |

**Two interleaved operations:** an on-prem hands-on-keyboard track (14:02 → ransomware) and a cloud-takeover
burst (07-16 02:11–03:02). The cloud burst happens overnight, between the two on-prem workdays.

## 2. User Correlation

| User | Endpoint activity | Cloud activity | Assessment |
| --- | --- | --- | --- |
| **jsmith** | Patient-zero: ran MSI, host of BumbleBee/AdaptixC2, created backup_EA | Sign-in from C2 IP (14:33); Kyiv takeover (02:11); elevated to Global Admin; disabled MFA/Security Defaults | Same identity abused on both planes — bridge account |
| **backup_EA / backup_ea** | Created on DC01 (4720/4728) as Enterprise Admin; NTDS/LSASS/Veeam theft, RDP, SSH, ransomware | Synced to cloud, added to "Global Admins", signed in from Amsterdam (09:14) | Attacker-created, dual-plane persistence |
| **itadmin** | Not seen on endpoint | Break-glass GA; role grant + rogue SP creation from Kyiv IP | Cloud-only in current logs — harvest point unknown (gap) |

## 3. IP Correlation — all three attacker IPs bridge both sources

| IP | Endpoint role | Cloud role | Verdict |
| --- | --- | --- | --- |
| **172.96.137.160** | AdaptixC2 beacon @14:32:03 | jsmith sign-in @14:33:52 | Confirmed pivot — 109 s apart, C2 host → cloud identity |
| **185.174.100.203** | SFTP exfil @23:41 | All Kyiv compromise sign-ins + every audit change (02:11–03:02) | Confirmed — one IP for cloud ops + on-prem exfil |
| **193.242.184.150** | Reverse-SSH tunnel @21:58 | backup_ea sign-in @09:14 | Confirmed — shared egress infra |

This IP overlap is the strongest link binding the two datasets into one campaign.

## 4. Attack Chain (unified)

1. **Initial access** — SEO-lure trojanized `ManageEngine-OpManager.msi`; jsmith runs it elevated on WS-IT-07
   → DLL side-load of BumbleBee (`consent.exe` loads unsigned `msimg32.dll`). *[High]*
2. **Endpoint foothold** — BumbleBee → AdaptixC2 (`AdgNsy.exe` via WMI + process injection); domain discovery;
   `backup_EA` Enterprise Admin created. *[High]*
3. **Pivot to cloud** — the AdaptixC2 host's IP signs into Azure AD 109 s after the beacon (14:33), harvesting a
   cloud token/credential from the foothold. Overnight (02:11) the attacker returns from Kyiv, brute-forces/replays
   jsmith, pulls in break-glass `itadmin`, and executes a ~40-min cloud takeover: Global Admin, rogue SP
   `backup-sync-connector` + secret, MFA/Security Defaults disabled, backup_ea → Global Admins.
   *[High on actions; Medium on exact credential source]*
4. **On-prem escalation & objective** — next morning: NTDS.dit + LSASS + Veeam credential theft, RustDesk
   persistence, reverse-SSH + SFTP exfil, then **Akira ransomware + shadow-copy deletion** on BKP01. *[High]*

**Ultimate objective: double extortion** — bulk data exfiltration followed by ransomware, with cloud tenant
takeover as parallel persistence/reach (mailbox access via SP `Mail.Read`, identity control that survives
on-prem cleanup).

## 5. Confidence Assessment

**Confident (High):**
- Same actor operates both planes — three shared attacker IPs + shared accounts, tight timestamp alignment.
- Full endpoint kill chain (initial access → ransomware) is directly evidenced.
- Cloud takeover sequence (GA elevation, rogue SP, MFA teardown) is directly evidenced in audit logs.
- The 14:32→14:33 C2-IP→sign-in pivot is a near-certain bridge.

**Uncertain (Medium/Low):**
- **Credential source for the 02:11 cloud sign-in.** Timing rules out the NTDS dump (07-16 09:21, ~7h later).
  Likely token/browser theft from the 07-15 AdaptixC2 foothold — but not directly observed.
- **How itadmin was compromised** — no endpoint evidence of itadmin credential harvest; account only appears cloud-side.
- **Brute force vs. token replay** at 02:11 (single failure→success in 32 s) — could be either; logs don't distinguish.
- **Exfil volume/contents** — SFTP connection confirmed; bytes transferred and what was taken are not in these logs.

## 6. Gaps — logs that would resolve the uncertainties

| Gap | Log to pull | Answers |
| --- | --- | --- |
| 02:11 credential origin | AAD token-issuance / sign-in authenticationDetails; browser-token theft telemetry on WS-IT-07 | Stolen PRT/refresh token vs. password? |
| itadmin harvest | Endpoint logs for itadmin's workstation; LSASS access (Sysmon 10) referencing itadmin | Where/how itadmin creds were taken |
| Exfil scope | Zeek/firewall/NetFlow byte counts to 185.174.100.203; FileZilla logs | Data volume + sensitivity |
| Mailbox abuse via SP | M365 Unified Audit Log / Exchange mailbox audit for appId b1e7c3a0…9a10 | Whether Mail.Read was exercised |
| Ransomware spread | Sysmon/Security from other hosts; DC replication of .akira | Full blast radius beyond BKP01 |
| Lateral auth detail | 4648 (explicit cred) / 4768–4769 (Kerberos/TGS) on DC01 | Credential reuse paths, Kerberoasting |
| C2 resolution | DNS logs for DGA ev2sirbd269o5j.org and full beacon set | Additional C2 infra / IOCs |

## Priority containment (derived)

1. Delete rogue SP `backup-sync-connector` (appId b1e7c3a0-9f21-4a55-8c14-77de0c2f9a10) + its secret — survives password resets.
2. Re-enable "Require MFA for admins" CA policy and Security Defaults.
3. Disable/reset jsmith, itadmin, backup_ea (on-prem + cloud); revoke refresh tokens.
4. Block 172.96.137.160, 185.174.100.203, 193.242.184.150.
5. Isolate WS-IT-07, DC01, FS01, BKP01; treat NTDS.dit as fully compromised → tenant-wide credential reset / krbtgt double-rotation.
