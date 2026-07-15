# mcp-hayabusa

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) - the Rust-based Windows event log (EVTX) threat-hunting CLI - so that Claude and other MCP clients can run EVTX scans and consume the results as structured JSON instead of parsing CLI text output.

It also doubles as a small **detection engineering knowledge base**: curated Sigma rules and MITRE ATT&CK technique coverage, exposed as browsable MCP resources alongside the scanning tools.

> Built as part of [module 3, "MCP – Wrapping Security CLIs"](https://www.justhacking.com/course/ai-cyber-defense-ops/), from Just Hacking Training's *AI Cyber Defense Ops* course.

## Why this exists

Hayabusa is a powerful detection tool, but every use of it means dropping into a terminal, remembering flag syntax, and reading through timeline output by hand. Wrapping it as an MCP server turns it into something an LLM-based analyst assistant can call directly, to scan a log, get back structured findings, reason about them, and correlate them with other data without re-implementing any of Hayabusa's parsing or detection logic. The server's only job is invocation, translation, filtering, and error handling; Hayabusa still does all the real work.

## What it exposes

**`scan_evtx`** - runs Hayabusa's `json-timeline` command against an `.evtx` file or a directory of them, and returns structured findings.

| Parameter | Description |
|---|---|
| `evtx_path` (required) | File or directory to scan |
| `min_severity` | Drop findings below `informational` / `low` / `medium` / `high` / `critical` |
| `rule_filter` | Case-insensitive substring match against each finding's rule title |
| `output_format` | `summary` (default, 7 key fields) or `full` (everything Hayabusa reports) |
| `max_results` | Truncate the result list; response reports `total_findings`, `returned_findings`, and `truncated` |

**`get_hayabusa_rules`** - lists detection rules parsed out of Hayabusa's rule set (~5,000 Sigma/Hayabusa YAML rules), so a client can see what exists *before* scanning.

| Parameter | Description |
|---|---|
| `keyword` | Case-insensitive substring match against title / description / id / tags |
| `max_results` | Truncate the result list |

Both tools return errors as structured JSON payloads (`{"error": "...", "message": "..."}`) with distinct error codes - `hayabusa_not_found`, `file_not_found`, `invalid_argument`, `scan_failed` - rather than raising opaque exceptions, so a client can branch on failure reliably.

## Detection engineering knowledge base

Alongside the scanning tools, the server exposes a small curated set of Sigma rules and their MITRE ATT&CK coverage as MCP resources:

| Resource URI | Returns |
|---|---|
| `detection://rules` | JSON metadata (title, level, tags, `technique_ids`, file path) for every curated Sigma rule |
| `detection://rules/{rule_name}` | Raw YAML of one rule, addressed by its file stem, e.g. `proc_creation_win_cmdkey_recon` |
| `detection://rules/by-technique/{technique_id}` | JSON list of rules tagged with a given ATT&CK technique (e.g. `T1003.001`); empty list if none match |
| `detection://attack/techniques/{technique_id}` | The technique's name/description/tactics (from MITRE ATT&CK data), which of our rules detect it, and a `covered` / `partial` / `gap` coverage verdict |

`rules/` holds 6 hand-picked Windows-scoped Sigma rules (sourced from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)), each mapped to a distinct ATT&CK technique:

| Rule | Technique | Tactic |
|---|---|---|
| UAC bypass via Empire PowerShell | T1548.002 | Privilege Escalation |
| Cached credential recon via `cmdkey` | T1003.005 | Credential Access |
| PowerShell downgrade attack | T1059.001 | Execution |
| Registry Run key persistence | T1547.001 | Persistence |
| LSASS memory dumping | T1003.001 | Credential Access |
| Cobalt Strike process injection | T1055.001 | Privilege Escalation |

ATT&CK technique names/descriptions come from a trimmed local copy of MITRE's public STIX data (`attack/techniques.json`, ~1.4MB / 858 techniques), generated once via `scripts/download_attack_data.py` from the full ~50MB [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) bundle so the server never has to load that directly. With only 6 rules, most of the 858 techniques will legitimately come back as `"gap"` - that reflects real coverage, not a bug.

### Coverage analysis tools

Two more tools turn the resource data above into something analytical, rather than just browsable:

**`analyze_coverage`** - aggregates the covered/partial/gap verdict across a whole ATT&CK tactic, or reports it for a single technique.

| Parameter | Description |
|---|---|
| `technique_id` | A single technique to analyze, e.g. `T1003.001` |
| `tactic` | All techniques under a tactic, e.g. `credential-access` (provide this or `technique_id`, not both) |

Returns a `coverage_summary` (covered/partial/gap counts), a `gaps` list, and full per-technique detail.

**`suggest_rule`** - checks whether a technique is covered, and if it's a gap, suggests a detection approach.

| Parameter | Description |
|---|---|
| `technique_id` (required) | ATT&CK technique to check, e.g. `T1003.006` |
| `create_template` | If `true` and it's a gap, write a starter Sigma rule into `rules/<category>/` |

If already covered, it says so and stops. Otherwise it searches Hayabusa's ~5,000 bundled rules for one already tagged with that technique (ranked by severity, deprioritizing `deprecated` rules) and recommends promoting it, or flags a genuine from-scratch gap. With `create_template=true`, the generated template's `logsource`/`detection` blocks are copied from the real candidate rule (not guessed), so it lands in the correct category folder - including new ones beyond the original five, e.g. `rules/security/` for a Security-log-sourced detection like DCSync.

## Example calls

```json
{"evtx_path": "test_data/UACME_59_Sysmon.evtx", "min_severity": "low"}
{"evtx_path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "rule_filter": "mimikatz", "max_results": 20}
{"keyword": "credential-access", "max_results": 10}
```

Tested against a real Sysmon EVTX sample from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) demonstrating UACME method 59 (UAC bypass) - scanning it unfiltered surfaces 8 findings across 3 rules, including the actual bypass technique (`New Process Created Via Taskmgr.EXE`).

Example resource reads:

```
detection://rules
detection://rules/proc_creation_win_cmdkey_recon
detection://rules/by-technique/T1003.001
detection://attack/techniques/T1003.001
```

Example coverage-analysis calls:

```json
{"tactic": "credential-access"}
{"technique_id": "T1558.003"}
{"technique_id": "T1003.006", "create_template": true}
```

## Architecture

```
MCP client (Claude)
      │  scan_evtx / get_hayabusa_rules       │  detection://rules/...       │  analyze_coverage / suggest_rule
      ▼                                        ▼                             ▼
 server.py  (mcp.server.Server, low-level API)
      │  subprocess                            │  reads rules/*.yml + attack/techniques.json
      ▼                                        ▼                             │
 hayabusa CLI (json-timeline -L -b ...)    Sigma tags → ATT&CK technique_ids → coverage verdict
      │  JSONL                                                               │
      ▼                                                                      ▼
 parse → filter → structured JSON response          aggregate across tactic, or rank Hayabusa's
                                                      bundled rules as promotion candidates,
                                                      optionally writing a new rules/*.yml template
```

- **Python**, using the low-level `mcp.server.Server` API (not `FastMCP`) for direct control over JSON Schema input validation and `TextContent` responses.
- Hayabusa is invoked via stdlib `subprocess`, never reimplemented - this project's value is the wrapping layer, not the detection engine.
- Output is parsed with Hayabusa's `-L` (JSONL) flag rather than its default `-o` JSON, which emits multiple pretty-printed objects with no valid separator between them.
- Rule metadata is parsed from YAML once per process and cached in memory (~7s cold across ~5,000 files, instant after).
- ATT&CK technique IDs are derived from each Sigma rule's `attack.tXXXX` tags at read time (regex), not stored in a separate mapping file - the rule YAML is the single source of truth.
- MITRE ATT&CK technique metadata is pre-extracted from the ~50MB public STIX bundle into a ~1.4MB local `attack/techniques.json` by `scripts/download_attack_data.py`, so the server loads a small static file instead of the full bundle.
- `analyze_coverage` and `suggest_rule` reuse the same rule-loading and coverage-scoring helpers as the `detection://...` resources rather than duplicating that logic - they're an analytical layer on top of the same data, not a second source of truth.
- `suggest_rule`'s promotion candidates are ranked by `(not-deprecated, severity, stable-status)`, so a maintained rule can't lose to a `deprecated` one just because they tie on severity.
- Generated rule templates copy their `logsource`/`detection` blocks directly from the seeding Hayabusa rule's own YAML, not a guess based on its file path - this determines both the template's content and which `rules/<category>/` subfolder it's written to.

## Skills demonstrated

- Designing an MCP tool interface (schemas, parameters, structured error contracts) around an existing security CLI
- Designing MCP resources (both concrete and templated URIs) as a read-only knowledge base layer, separate from the tool-call interface
- Debugging real integration issues by working from actual tool output rather than assumptions - e.g. discovering Hayabusa's `-b` flag is required because it abbreviates `informational` → `info` by default, silently breaking severity filtering
- Threat-hunting fundamentals: EVTX/Sysmon telemetry, Sigma-rule-based detection, MITRE ATT&CK tagging conventions
- Turning a detection ruleset into a queryable coverage model (technique → rules → covered/partial/gap) instead of just a flat rule list
- Building analysis tools (`analyze_coverage`, `suggest_rule`) on top of existing resource data instead of duplicating it, including ranking heuristics that hold up under real edge cases (deprecated-vs-maintained rules, mis-inferred logsources) found through actual testing, not assumption
- Treating an external CLI dependency as an untrusted boundary: failing fast and explicitly (missing binary, missing file, non-zero exit) instead of degrading silently

## Setup

```powershell
pip install -r requirements.txt          # mcp SDK + pyyaml
python scripts/download_hayabusa.py      # fetches the Hayabusa release binary + rules
python scripts/download_attack_data.py   # fetches ATT&CK technique data (name/description/tactics)
python test_scan.py                      # smoke test against the sample EVTX
```

Registered as a Claude Code project-scoped MCP server via `.mcp.json` - run `/mcp` to connect, then call `scan_evtx` / `get_hayabusa_rules`, or read a `detection://...` resource, like any other tool.

> Note: `.mcp.json` points at a hardcoded local Python interpreter path. It works as-is on the machine it was built on, but you'll need to update that path (or point it at your own `python`/`python3` on `PATH`) to run it elsewhere.

## Known limitations

- `rule_filter` filters findings *after* the scan runs (Hayabusa has no free-text "only run rules matching X" flag) - it doesn't reduce which rules actually execute.
- No automated (pytest) test suite yet; verification so far is a manual smoke script (`test_scan.py`) plus an uncommitted ad-hoc script for the `detection://...` resources.
- Linux/macOS code paths are written but have only been exercised on Windows.
- No pagination beyond `max_results` truncation.
- Only 6 curated Sigma rules exist so far, so ATT&CK coverage queries will mostly report `"gap"` - that's a reflection of the small sample set, not a scanning bug.
- `attack/techniques.json` must be regenerated via `scripts/download_attack_data.py` if it's missing or stale; the server doesn't fetch it on demand.
- `suggest_rule` can only find a promotable candidate among Hayabusa's bundled rules or our own curated set - both are Windows-EVTX-scoped, so techniques whose telemetry lives elsewhere (e.g. T1675 ESXi Administration Command, which needs ESXi host logs) will always come back as a from-scratch gap with no candidates.
- A running MCP connection doesn't pick up new/changed tools automatically - after editing `server.py`, a full reconnect (or Claude Code restart) is needed before new tools like `analyze_coverage`/`suggest_rule` are callable through the MCP interface.

See [HANDOFF.md](HANDOFF.md) for the full build narrative and every decision's rationale, and [STATE.md](STATE.md) for the current checkpoint.
