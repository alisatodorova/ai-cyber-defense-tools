# Threat Intel Analysis: ClickFix → Matanbuchus 3.0 → AstarionRAT (Huntress, Feb 2026)

**Source:** https://www.huntress.com/blog/clickfix-matanbuchus-astarionrat-analysis
**Ingested:** 2026-08-04
**Summary:** Hands-on-keyboard intrusion starting with a ClickFix paste-and-run lure delivering a silent MSI. Chain: MSI → Zillya AV DLL sideload → Matanbuchus 3.0 loader (ChaCha20, EDR-unhooking, embedded Lua interpreter, reflective PE loader) → **AstarionRAT** (new 24-command custom implant, RSA-encrypted C2 disguised as telemetry). Operator hit two DCs in under 40 minutes via PsExec, rogue accounts, and Defender exclusions. Assessed (medium confidence) as pre-ransomware.

## Extracted TTPs

| Technique | ID | Confidence | Priority |
|-----------|-----|------------|----------|
| ClickFix — malicious copy/paste into Run dialog | T1204.004 | High | **Simulate** |
| Msiexec silent remote install (`msiexec /q PACKAGE=http://…`) | T1218.007 | High | **Simulate** |
| DLL side-loading (Zillya `core.exe`+`SystemStatus.dll`; `java.exe`+`jli.dll`) | T1574.002 | High | **Simulate** |
| Masquerading — renamed 7-Zip (`aps.exe`), fake vendor paths | T1036 / T1036.005 | High | **Simulate** |
| Match legit name/location — `C:\ProgramData\USOShared\` staging | T1036.005 | High | **Simulate** |
| Deobfuscate/decode (ChaCha20, rolling XOR, custom base64) | T1140 | High | Simulate (proxy) |
| Obfuscated/encrypted payloads; password-protected 7z archive | T1027 / T1027.013 | High | **Simulate** |
| Security software discovery (EDR process-name enumeration) | T1518.001 | High | **Simulate** |
| Sandbox/VM evasion (junk API calls, busy-loops) | T1497.003 | Medium | Skip (loader-internal) |
| Impair defenses — EDR unhooking (restore ntdll/kernel32) | T1562.001 | High | Simulate (careful) |
| Reflective code loading (Lua→shellcode→reflective PE loader) | T1620 | High | Simulate (proxy) |
| Scheduled task persistence — `Application Maintenance` → `Core.exe` | T1053.005 | High | **Simulate** |
| Service execution (`sc start AppMgmt`) | T1569.002 | High | **Simulate** |
| Domain group discovery (`net groups "Domain Admins" /domain`) | T1069.002 | High | **Simulate** |
| Remote system discovery (`nltest /dclist:`) | T1018 | High | **Simulate** |
| Create local account (`net user DefaultService … /add`) | T1136.001 | High | **Simulate** |
| Account manipulation — add to Administrators/`Administradores` | T1098 | High | **Simulate** |
| Lateral movement — RDP | T1021.001 | High | **Simulate** |
| Lateral movement — PsExec over SMB admin shares | T1021.002 | High | **Simulate** |
| Impair defenses — Defender path exclusion | T1562.001 | High | **Simulate** |
| Web C2, encrypted channel disguised as telemetry | T1071.001 / T1573 | High | Simulate (proxy) |
| Traffic disguised as app telemetry (data obfuscation) | T1001 | Medium | Skip (RAT-internal) |
| Internal proxy — SOCKS5 (XOR-obfuscated) | T1090.001 | Medium | Skip (RAT-internal) |
| Network service scanning (port scanner) | T1046 | Medium | **Simulate** |
| Credential theft / impersonation | T1003 / T1134 | Medium | **Simulate** |
| Acquire/register infrastructure — brand-impersonation domains | T1583.001 | High | Skip (recon-only) |

## Simulation Plan

Lab: **ConDef** (DC, Win11v w/ Sysmon, Splunk). All of the below are safe to run on the isolated Win11v workstation and DC; C2/loader internals are simulated with benign proxies (Atomic-style) rather than live malware.

### Phase 1: Initial Access & Execution
- **ClickFix (T1204.004):** Simulate the Run-dialog paste with a benign `msiexec` invocation to a lab-hosted MSI. Reproduce the mixed-casing evasion string `mSiexeC.EXe … /q` to test string-match rules.
- **Msiexec remote install (T1218.007):** Host a benign MSI on a lab web server; run `msiexec /q PACKAGE=http://<lab>/test.msi`. Capture Event ID 1116/msiexec proc-create telemetry.

### Phase 2: Defense Evasion & Persistence
- **DLL side-loading (T1574.002):** Use a signed legit binary + planted DLL in a user-writable dir (Atomic T1574.002 tests) to confirm Sysmon EID 7 image-load detection.
- **Masquerade + USOShared staging (T1036.005):** Drop benign EXEs into `C:\ProgramData\USOShared\` and a renamed 7-Zip (`aps.exe`) extracting a password-protected `.7z`. Test path-based alerting.
- **Scheduled task (T1053.005):** `schtasks /create /tn "Application Maintenance" /tr "C:\ProgramData\<rand>\Core.exe" …` → EID 4698.
- **Service execution (T1569.002):** `sc start AppMgmt` → EID 7045/7036.
- **Defender exclusion (T1562.001):** `Add-MpPreference -ExclusionPath C:\ProgramData\USOShared\` → Defender Operational EID 5007 (revert after).

### Phase 3: Discovery
- `net groups "Domain Admins" /domain` (T1069.002)
- `nltest /dclist:` (T1018)
- `net user … /add` + `net localgroup Administrators/Administradores … /add` (T1136.001 / T1098) — **test both the Spanish and English group names**
- Benign port scan from Win11v → DC (T1046)

### Phase 4: Lateral Movement
- **PsExec (T1021.002):** `psexec.exe -accepteula -s -d \\<dc> c:\programdata\usoshared\test.bat` → EID 4624 type 3, 5145, 7045. Push to DC and member server as in the report.
- **RDP (T1021.001):** Interactive RDP with the rogue `DefaultService` account → EID 4624 type 10 / 4778.

## Infrastructure Requirements
- Lab web server to host benign MSI (mimics `binclloudapp[.]com/466943`).
- A second Windows host (member server or Backup DC) to exercise the PsExec DC-to-DC pivot chain.
- Benign DLL-sideload test kit and a signed host binary (Atomic Red Team provides these).
- Sysmon config with image-load (EID 7) and network-connect logging enabled on all targets.
- **Do not** detonate live Matanbuchus/AstarionRAT samples in the ConDef lab unless fully network-isolated — proxy the loader/C2 behaviors instead.

## Detection Opportunities
- **Msiexec** spawning with a remote `PACKAGE=http(s)://` argument or mixed-case binary name; child processes of `msiexec.exe`.
- **Process lineage:** `explorer.exe`/browser → `powershell.exe`/`cmd.exe`/`msiexec.exe` shortly after a Run-dialog (RunMRU registry write is a strong ClickFix indicator).
- **Sideloading:** legit signed EXE loading a DLL from `%APPDATA%`, `ProgramData`, or a vendor-lookalike path (EID 7).
- **Staging paths:** any executable creation/execution under `C:\ProgramData\USOShared\` (not a normal exec location).
- **Rogue accounts:** EID 4720 (create) + 4732 (add to Administrators), especially the localized group name `Administradores`; correlate with PsExec/`-s` SYSTEM context.
- **PsExec:** `PSEXESVC` service install (EID 7045), EID 5145 on `ADMIN$`, remote proc-create from `USOShared`.
- **Scheduled task** `Application Maintenance` or any task pointing at `ProgramData\<hex>\`.
- **Defender exclusion** additions (EID 5007) followed closely by a quarantine event — the report notes exclusion set *after* detection.
- **C2:** GET `/intake/organizations/events?channel=app`, UA `Edge/18.19045`, `Accept-Language: zh-CN`, cookie fields `AFUAK=`/`BLA=`/`HFK=`; 10-second beacon interval.

## IOCs
| Indicator | Type | Notes |
|-----------|------|-------|
| `binclloudapp[.]com` | Domain | Payload delivery; created 2026-02-05 |
| `sectigoapps[.]com` | Domain | Same IP, brand impersonation |
| `solidclouaps[.]com` | Domain | Same IP, brand impersonation |
| `192.121.23[.]146` | IP | M247 Europe SRL, AS9009 (Germany) |
| `www.ndibstersoft[.]com` | Domain | AstarionRAT C2 |
| `<archive-pw>` (redacted) | Archive password | `TMP412.7z` (Zillya sideload package) |

**YARA (from report):**
- AstarionRAT: https://github.com/RussianPanda95/Yara-Rules/blob/main/AstarionRAT/win_mal_AstarionRAT.yar
- Matanbuchus 3.0 loader: https://github.com/RussianPanda95/Yara-Rules/blob/main/Matanbuchus/win_mal_Matanbuchus_loader.yar
