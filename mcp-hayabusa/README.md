# mcp-hayabusa

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) - the Rust-based Windows event log (EVTX) threat-hunting CLI - so that Claude and other MCP clients can run EVTX scans and consume the results as structured JSON instead of parsing CLI text output.

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

## Example calls

```json
{"evtx_path": "test_data/UACME_59_Sysmon.evtx", "min_severity": "low"}
{"evtx_path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "rule_filter": "mimikatz", "max_results": 20}
{"keyword": "credential-access", "max_results": 10}
```

Tested against a real Sysmon EVTX sample from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) demonstrating UACME method 59 (UAC bypass) - scanning it unfiltered surfaces 8 findings across 3 rules, including the actual bypass technique (`New Process Created Via Taskmgr.EXE`).

## Architecture

```
MCP client (Claude)
      │  scan_evtx / get_hayabusa_rules
      ▼
 server.py  (mcp.server.Server, low-level API)
      │  subprocess
      ▼
 hayabusa CLI (json-timeline -L -b ...)
      │  JSONL
      ▼
 parse → filter → structured JSON response
```

- **Python**, using the low-level `mcp.server.Server` API (not `FastMCP`) for direct control over JSON Schema input validation and `TextContent` responses.
- Hayabusa is invoked via stdlib `subprocess`, never reimplemented - this project's value is the wrapping layer, not the detection engine.
- Output is parsed with Hayabusa's `-L` (JSONL) flag rather than its default `-o` JSON, which emits multiple pretty-printed objects with no valid separator between them.
- Rule metadata is parsed from YAML once per process and cached in memory (~7s cold across ~5,000 files, instant after).

## Skills demonstrated

- Designing an MCP tool interface (schemas, parameters, structured error contracts) around an existing security CLI
- Debugging real integration issues by working from actual tool output rather than assumptions - e.g. discovering Hayabusa's `-b` flag is required because it abbreviates `informational` → `info` by default, silently breaking severity filtering
- Threat-hunting fundamentals: EVTX/Sysmon telemetry, Sigma-rule-based detection, MITRE ATT&CK tagging conventions
- Treating an external CLI dependency as an untrusted boundary: failing fast and explicitly (missing binary, missing file, non-zero exit) instead of degrading silently

## Setup

```powershell
pip install -r requirements.txt          # mcp SDK + pyyaml
python scripts/download_hayabusa.py      # fetches the Hayabusa release binary + rules
python test_scan.py                      # smoke test against the sample EVTX
```

Registered as a Claude Code project-scoped MCP server via `.mcp.json` - run `/mcp` to connect, then call `scan_evtx` / `get_hayabusa_rules` like any other tool.

> Note: `.mcp.json` points at a hardcoded local Python interpreter path. It works as-is on the machine it was built on, but you'll need to update that path (or point it at your own `python`/`python3` on `PATH`) to run it elsewhere.

## Known limitations

- `rule_filter` filters findings *after* the scan runs (Hayabusa has no free-text "only run rules matching X" flag) - it doesn't reduce which rules actually execute.
- No automated (pytest) test suite yet; verification so far is a manual smoke script.
- Linux/macOS code paths are written but have only been exercised on Windows.
- No pagination beyond `max_results` truncation.

See [HANDOFF.md](HANDOFF.md) for the full build narrative and every decision's rationale, and [STATE.md](STATE.md) for the current checkpoint.
