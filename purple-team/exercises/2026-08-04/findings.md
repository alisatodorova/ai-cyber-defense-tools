# Detection Findings — 2026-08-04

**Scan engine:** Hayabusa 3.10.0 (via `hayabusa` MCP `scan_evtx`)
**Input:** `exercises/2026-08-04/evtx/{security.evtx, sysmon.evtx}` — synthetic EVTX generated from the
rendered sample XML for this exercise (single BinXML chunk; consumer-validated by parsing 10/10 events).
**Scope:** all events dated 2026-08-04.
**Rules loaded:** 4,642 (181 Hayabusa + 4,461 Sigma).
**Result:** 21 detections across 10 events — 6 high / 6 medium / 9 low.

## Focus technique 1 — Domain Groups (T1069.002)

Attacker action: `net group "Domain Admins" /domain` (via AstarionRAT dispatcher → cmd.exe → net.exe → net1.exe)

| Rule | Severity | Event | Record |
|------|----------|-------|--------|
| Proc Exec (Sysmon Alert) | high | Sysmon 1 (net.exe) | 184402 |
| Proc Exec (Sysmon Alert) | high | Sysmon 1 (net1.exe) | 184403 |
| Suspicious Group And Account Reconnaissance Activity Using Net.EXE | medium | Sysmon 1 | 184402, 184403 |
| Net.EXE Execution | low | Sysmon 1 | 184402, 184403 |

Both the `net.exe` invocation and its `net1.exe` child were detected.

## Focus technique 2 — Create Local Admin (T1136.001 / T1098)

Attacker action: `net user DefaultService <password> /add` then add to Administradores (fail) / Administrators (success)

| Rule | Severity | Event | Record |
|------|----------|-------|--------|
| User Added To Local Admin Grp | high | Security 4732 | 994003 |
| Proc Exec (Sysmon Alert) | high | Sysmon 1 (net user/localgroup) | 184501, 184505, 184611 |
| Password Reset By Admin | medium | Security 4724 | 993219 |
| New User Created Via Net.EXE | medium | Sysmon 1 | 184501 |
| User Added to Local Administrators Group | medium | Sysmon 1 | 184611 |
| Local User Account Created | low | Security 4720 | 993217 |
| Net.EXE Execution | low | Sysmon 1 | 184501, 184505, 184611 |

## Bundled discovery — Remote System Discovery (T1018)

Attacker action: `nltest /dclist:condef.local`

| Rule | Severity | Event | Record |
|------|----------|-------|--------|
| Potential Recon Activity Via Nltest.EXE | medium | Sysmon 1 | 184409 |
| Nltest.EXE Execution | low | Sysmon 1 | 184409 |
| Renamed Exe File | low | Sysmon 1 | 184409 |

## Severity roll-up

| Severity | Count |
|----------|------:|
| high | 6 |
| medium | 6 |
| low | 9 |
| **Total** | **21** |

## Notes / detection gaps

- **`net localgroup Administradores …` (the operator's Spanish-first tell):** fired only the low
  "Net.EXE Execution" process rule and produced **no 4732** — expected, because the localized group
  does not exist on an English-locale host, so no group-membership audit is generated. Detection must
  rely on the **process command line**, not the 4732 audit or the well-known SID `S-1-5-32-544`.
- **Provenance:** EVTX is synthetic (generated for this exercise). The Sigma/Hayabusa detection logic
  exercised is production; only the events are synthetic. A live-lab run would add EDR-native fields,
  real file hashes, and true process GUIDs.
- **Highest-value alerts** to promote to the SIEM: `User Added To Local Admin Grp` (4732, high) and
  the Sysmon proc-exec alerts on recon + account creation (high).
