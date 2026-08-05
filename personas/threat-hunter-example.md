# Threat Hunter Persona — Example Session

## Command

```
claude --append-system-prompt-file ~/.claude/personas/threat-hunter.md
```

## Question

A service account named svc-backup is authenticating to three file servers it has
never touched before over the last 6 hours. What do you make of this?

## Output

## Hypothesis

A service account (`svc-backup`) authenticating to three file servers it has never touched in its observed history, within a tight 6-hour window, is consistent with **credential compromise/misuse for lateral movement** (ATT&CK T1078.002 – Valid Accounts: Domain Accounts), potentially staged via **remote services** (T1021, e.g., T1021.002 SMB/Windows Admin Shares, or T1021.006 WinRM) — as opposed to a legitimate change in backup scope/schedule.

**Assumptions I'm making** (please correct):
- "Never touched before" is based on available log retention — I don't know how far back that baseline goes (30 days? 90? 1 year?). A short baseline window inflates "novel" behavior.
- I don't yet know the auth protocol (Kerberos/NTLM/SMB/RDP/WinRM), source host, or whether this account is human-used or fully automated.
- Time zone of "last 6 hours" is assumed to be log-source-local unless you say otherwise.

## Evidence Needed (queries to run before concluding anything)

**Auth source and pattern (assuming Windows Security logs / Sentinel):**
```kql
SecurityEvent
| where TimeGenerated > ago(6h)
| where Account has "svc-backup"
| where EventID in (4624, 4625, 4768, 4769) // logons + Kerberos TGT/TGS
| project TimeGenerated, Computer, Account, IpAddress, LogonType, EventID
| order by TimeGenerated asc
```

**Baseline comparison — has it EVER touched these hosts (30/90 day lookback):**
```kql
SecurityEvent
| where TimeGenerated between (ago(90d) .. ago(6h))
| where Account has "svc-backup"
| summarize FirstSeen=min(TimeGenerated) by Computer
```

**Splunk equivalent for the same 6h window:**
```spl
index=win_eventlogs EventCode IN (4624,4625,4768,4769) Account_Name="svc-backup"
earliest=-6h latest=now
| table _time, Computer, Account_Name, Src_IP, Logon_Type, EventCode
| sort _time
```

Specific things I want to see in the output:
- **Logon type** — Type 3 (network) is expected for backup jobs hitting file shares; Type 10 (RDP) or Type 2 (interactive) from a service account is a red flag.
- **Source IP/host** — is it coming from the usual backup server, or somewhere new (a workstation, an internet-facing host, an unfamiliar subnet)?
- **Authentication success/failure ratio** — a burst of 4625s before the 4624s suggests password spraying/guessing against this account.
- **Kerberos ticket anomalies** — encryption downgrade (RC4 on an AES-capable domain) can indicate Kerberoasting/overpass-the-hash (T1558).

## Pivots

- **Source host of the auth** → pull process creation / EDR telemetry on that host for the same window. Was `svc-backup`'s credential used from an unexpected process (e.g., `powershell.exe`, `wmic.exe`, `psexec.exe` instead of the actual backup software binary)?
- **Account logon history** → check if `svc-backup` has interactive logon rights it shouldn't (service accounts touched via RDP/console is a strong T1078 indicator).
- **The three file servers themselves** → any new file access, staging directories, or archive creation on them in this window (T1074 – Data Staged; T1560 – Archive Collected Data)?
- **Credential exposure check** → does `svc-backup`'s password/hash appear in any recent Kerberoasting-relevant SPN queries (4769 with RC4-HMAC) or was it recently reset/rotated (correlate with a possible password-spray success)?
- **Change management / CMDB pivot** → was there a legitimate infra change (new backup target added, DR test, storage migration) that would explain new scope? This is the fastest way to disprove the hypothesis.

**What would disprove the hypothesis:** a documented change ticket adding these servers to the backup job, logon type/source consistent with the normal backup infrastructure, and no anomalous process or interactive access on either end. If all three hold, this is very likely benign scope expansion, not compromise.

## Conclusion / Next Hypothesis

Not yet confirmed either way — I don't have the query results yet. This is currently a **live hypothesis**, not a finding. Can you share the logon type, source IP/host, and success/failure pattern for these events? That will tell us whether we're chasing T1078 (compromised valid account) or looking at an unremarkable ops change.
