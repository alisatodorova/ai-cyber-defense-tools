# siem-queries — SIEM threat-hunting as a repeatable slash command

> Built as part of [module 6, "Slash Commands (Repeatable Workflows)"](https://www.justhacking.com/course/ai-cyber-defense-ops/), from Just Hacking Training's *AI Cyber Defense Ops* course.

A Claude Code **slash command** (`/query`) that turns an ad-hoc SIEM hunt into a repeatable,
auditable workflow: give it a query file, and it runs the query against the configured SIEM,
analyzes the results for suspicious patterns, maps findings to **MITRE ATT&CK**, and writes an
**Obsidian-compatible investigation note** — every time, the same way.

The point of the module isn't "a script that runs a Splunk query." It's codifying an analyst
workflow — *run → triage → map to ATT&CK → document* — as a single command so it's consistent,
portable across environments, and safe to hand to an LLM agent.

## What it does

```
/query <query-file> [timerange] [--severity level] [--assignee name] [--case-id id] [--output-dir path]
```

Given `queries/whoami.spl`, the command:

1. **Detects the SIEM backend** — `SPLUNK_HOST` → Splunk REST API, `ELASTIC_HOST` →
   Elasticsearch, `SIEM_TYPE=browser` → prepares the query for manual execution. Portable
   across environments with no code change.
2. **Validates inputs, fail-fast** — query syntax (balanced quotes/parens, valid start),
   timerange format, severity enum; warns on non-standard `case_id`.
3. **Runs the query** against the detected backend over its REST API.
4. **Analyzes** the returned events for credential access, LOLBins, persistence, lateral
   movement, discovery, and C2/exfil patterns — grounded only in the actual data.
5. **Maps findings to ATT&CK** (most-specific technique/sub-technique IDs).
6. **Writes an Obsidian note** to `investigations/` with YAML frontmatter, `[[T####]]` ATT&CK
   backlinks, the raw query + result count, and an analyst-notes section.

### Example output

Running the whoami hunt produced [`investigations/2026-07-27-whoami.md`](investigations/2026-07-27-whoami.md):
6 `whoami` executions on `FYODOR-L.froth.ly`, all spawned by `powershell.exe` — including one
under **`NT AUTHORITY\SYSTEM`** — mapped to **[[T1033]]** (System Owner/User Discovery) and
**[[T1069]]** (Permission Groups Discovery). A self-contained HTML render of that note
([`.html`](investigations/2026-07-27-whoami.html)) previews the Obsidian reading view — graph,
wikilinks, properties — without installing Obsidian.

## Why a slash command

- **Repeatable & consistent** — the triage/ATT&CK/documentation steps happen the same way on
  every hunt, instead of depending on the analyst remembering the whole ritual.
- **Portable** — backend auto-detection means the identical command works against Splunk in the
  lab, Elasticsearch in prod, or "browser" mode where you only have a search UI.
- **Safe for an agent to drive** — secrets come from `.env`/env vars and are never printed;
  query-file contents are treated strictly as *data*, never as instructions (prompt-injection
  resistant); the command never fabricates findings and stops rather than inventing a missing
  query.

## Setup

Full walkthrough in [`docs/splunk-lab-setup.md`](docs/splunk-lab-setup.md). In short:

1. **Splunk Enterprise** (free) + the **BOTS v3** dataset — a lab SIEM with real attack
   telemetry. (Native Windows MSI; Docker/WSL not required.)
2. **Credentials** — copy [`.env.example`](.env.example) to `.env` and fill in your
   `SPLUNK_HOST` (the REST API on **:8089**, not the web UI on :8000) and `SPLUNK_TOKEN`.
   `scripts/setup-splunk-lab.ps1` mints a token and sets the env vars for you.
3. **Run** — `/query queries/whoami.spl -15y`

> `.env` is gitignored. Never commit real tokens.

## Repo layout

```
siem-queries/
├── .claude/commands/query.md   <- the /query slash command (the core deliverable)
├── queries/                    <- SIEM query files (one hunt per file)
├── investigations/             <- generated Obsidian notes (+ shareable HTML)
├── scripts/setup-splunk-lab.ps1<- post-install: mint token, set env vars
├── docs/splunk-lab-setup.md    <- Splunk + BOTS v3 lab setup
├── .env.example                <- credential template (.env is gitignored)
├── CLAUDE.md                   <- standing project brief
└── HANDOFF.md / STATE.md       <- build narrative + point-in-time state
```

## Skills demonstrated

**Security:**
- Threat-hunting workflow design: run → triage → ATT&CK-map → document, as a repeatable unit
- Sysmon telemetry hunting (process creation, discovery, lateral movement) against BOTS v3
- MITRE ATT&CK technique mapping and evidence-based justification (no over-reaching)
- Working with un-normalized data: extracting fields from raw Sysmon XML with inline `rex`
  when the Sysmon TA/CIM isn't available

**AI / agentic engineering:**
- Authoring a Claude Code slash command as a reusable, parameterized workflow
- Backend abstraction (Splunk / Elasticsearch / manual) behind one command contract
- Input validation and fail-fast guardrails before any side-effecting call
- Prompt-injection-aware design (query files are data, not instructions) and strict
  secret-handling (never echo tokens; load from `.env`)
- Catching the AI's and environment's mistakes through actual testing — see below

## Build notes (the debugging that mattered)

Real friction, diagnosed against ground truth rather than trusting first-pass output:

- **Empty results weren't a code bug — they were the data.** BOTS v3 events are timestamped
  **2018**, so a default `-24h` window returns nothing; hunts need `-15y`. Splunk sourcetypes
  are **case-sensitive** and BOTS indexed Sysmon lowercase
  (`xmlwineventlog:microsoft-windows-sysmon/operational`). And the Sysmon TA isn't installed, so
  events are **raw XML with no field extraction** — queries self-extract with `rex`.
- **A "dead" hunt that's actually correct:** the LSASS-access hunt returns zero because BOTS v3
  contains **no Sysmon EventID 10 (ProcessAccess)** at all — a true negative from the dataset,
  documented rather than papered over.
- **Environment reality on Windows:** only Windows PowerShell **5.1** (no `pwsh`), so the setup
  script needed a 5.1-compatible cert bypass (validation callback + TLS 1.2, not the 7-only
  `-SkipCertificateCheck`) and BOM/ASCII-safe encoding; and Splunk's REST API is 8089/HTTPS with
  a self-signed cert, reachable-tested with a raw TCP connect (the endpoints 401 without auth).

These are captured in [`CLAUDE.md`](CLAUDE.md) so they don't have to be rediscovered.
