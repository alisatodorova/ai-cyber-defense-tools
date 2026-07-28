# STATE.md — point-in-time snapshot

_Last updated: 2026-07-27_

A factual snapshot of the environment and repo. For "what to do next," see `HANDOFF.md`.

## Infrastructure

| Component | State | Detail |
|---|---|---|
| Splunk Enterprise | **Installed, service STOPPED** | v10.4.1, server `<splunk-host>`, role `indexer` |
| Splunk service | `Splunkd` = Stopped (Automatic) | Needs **admin** `Start-Service Splunkd` |
| REST API | `https://localhost:8089` | HTTPS, self-signed cert; unreachable while stopped |
| Web UI | `http://localhost:8000` | Not the API — do not point tools here |
| BOTS v3 dataset | **Loaded** | `index=botsv3`, ~1.9M events across Sysmon/Stream/AWS/osquery/Symantec |
| Docker / WSL | **Not installed** | Native Splunk chosen instead |
| PowerShell | **5.1 only** (`powershell.exe`) | No `pwsh`; session is **not admin** |

## Credentials / config

| Item | State |
|---|---|
| `.env` | Present (gitignored) — `SPLUNK_HOST`, `SPLUNK_TOKEN` |
| `SPLUNK_HOST` | `https://localhost:8089` (User env + `.env`) |
| `SPLUNK_TOKEN` | Set, 472-char JWT (persisted at User scope; not printed) |
| Elasticsearch / browser backends | Not configured (Splunk auto-detected) |

## Repo contents

| Path | Purpose | Status |
|---|---|---|
| `.claude/commands/query.md` | `/query` command | Multi-SIEM + args + validation |
| `queries/whoami.spl` | Discovery hunt (T1033/T1069) | ✅ returns data |
| `queries/lateral-movement.spl` | Lateral-movement hunt | Created, **not yet run/validated** |
| `queries/lsass-access.txt` | LSASS hunt | Dead end — no EC10 in BOTS v3 |
| `queries/powershell-encoded.txt` | PowerShell hunt | Needs sourcetype-case + inline-rex fix |
| `queries/scheduled-task-persistence.txt` | Persistence hunt | Needs sourcetype-case + inline-rex fix |
| `investigations/2026-07-27-whoami.md` | Completed note | ✅ real findings |
| `investigations/2026-07-27-whoami.html` | Shareable Obsidian render | ✅ self-contained |
| `investigations/2026-07-27-lsass-access.md` | No-data note | Closed (no EC10) |

## Query results captured so far

| Query | Timerange | Result | ATT&CK |
|---|---|---|---|
| whoami | -15y | 6 executions on FYODOR-L.froth.ly (incl. SYSTEM via powershell) | T1033, T1069 |
| lsass-access | -15y / earliest=0 | 0 (no EventID 10 in dataset) | — |

## Known-good query pattern (BOTS v3, no Sysmon TA)

```spl
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" "<EventID>1</EventID>" <keyword>
| rex "Name=.CommandLine.>(?<CommandLine>[^<]+)"
| rex "<Computer>(?<Computer>[^<]+)"
| stats count by Computer ...
```
