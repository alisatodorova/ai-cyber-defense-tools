# HANDOFF

Status snapshot of the Hayabusa MCP server as of 2026-07-14. See [CLAUDE.md](CLAUDE.md) for the
standing project brief; this file is the point-in-time "what happened and what's next."

## What we built

An MCP server ([server.py](server.py)) that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa)
EVTX analysis CLI and exposes two tools:

- **`scan_evtx`** — runs Hayabusa's `json-timeline` command against an `.evtx` file or directory
  and returns structured JSON findings.
  - `evtx_path` (required) — file or directory.
  - `min_severity` — one of `informational`/`low`/`medium`/`high`/`critical`; findings below this
    level are dropped.
  - `rule_filter` — case-insensitive substring match against each finding's `RuleTitle`.
  - `output_format` — `"summary"` (default; 7 key fields per finding) or `"full"` (everything
    Hayabusa reports, including `Details`/`ExtraFieldInfo`/`RuleID`).
  - `max_results` — truncates the returned list; response includes `total_findings` (pre-truncation),
    `returned_findings`, and a `truncated` flag so callers can tell results were cut.
- **`get_hayabusa_rules`** — lists detection rules parsed out of `./hayabusa/rules/**/*.yml`
  (title, id, level, status, ruletype, tags, description, file path), so a client can see what
  rules exist before scanning.
  - `keyword` — case-insensitive substring match against title/description/id/tags.
  - `max_results` — same truncation pattern as above.
  - Rule metadata is parsed once per server process and cached in memory (~7s cold on ~5,000
    rule files, ~instant after).

Both tools return errors as JSON payloads (`{"error": "...", "message": "..."}`) inside the
`TextContent` block rather than raising protocol-level errors, with distinct codes:
`hayabusa_not_found`, `file_not_found`, `invalid_argument`, `scan_failed`.

Supporting pieces:

- [scripts/download_hayabusa.py](scripts/download_hayabusa.py) — downloads the latest Hayabusa
  release for the current OS/arch from GitHub and extracts it to `./hayabusa/`. Already run once;
  `./hayabusa/` contains the v3.10.0 Windows x64 binary, `config/`, and `rules/`.
- [test_scan.py](test_scan.py) — manual smoke test: imports `server` directly and calls
  `scan_evtx` against a real sample.
- [test_data/UACME_59_Sysmon.evtx](test_data/UACME_59_Sysmon.evtx) — a real Sysmon EVTX sample
  (from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)) showing a
  UAC-bypass technique (UACME method 59), used for all manual testing.
- [.mcp.json](.mcp.json) — registers this server as `hayabusa` for Claude Code's project-scoped
  MCP config, so it's reachable via `/mcp`.
- [docs/hayabusa_rules_poc.pptx](docs/hayabusa_rules_poc.pptx) — a slide deck walking through
  3 of the rules that fired against the sample EVTX, built as a proof-of-concept demo.
- [requirements.txt](requirements.txt) — `mcp` (MCP SDK) and `pyyaml` (parses rule YAML for
  `get_hayabusa_rules`).

## How to use it

```powershell
pip install -r requirements.txt          # install mcp + pyyaml
python scripts/download_hayabusa.py      # only needed once, or to refresh the Hayabusa build
python test_scan.py                      # sanity check: scans test_data/UACME_59_Sysmon.evtx
```

To use it as an MCP server in Claude Code: `.mcp.json` already registers it as `hayabusa` for
this project directory. Run `/mcp` (or fully restart Claude Code — see **Known issue** below) to
connect, then call `scan_evtx` / `get_hayabusa_rules` like any other tool.

Example calls:

```json
{"evtx_path": "test_data/UACME_59_Sysmon.evtx", "min_severity": "low"}
{"evtx_path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "rule_filter": "mimikatz", "max_results": 20}
{"keyword": "credential-access", "max_results": 10}
```

Note: `keyword`/`rule_filter` are plain substring matches, not MITRE-tactic-aware. To find rules
for a specific ATT&CK tactic, match the hyphenated tag format Sigma/Hayabusa actually use (e.g.
`credential-access`, not `credential_access` or `credential access`) — see **Decisions** below.

## What's left to do

- **Reconnect the running MCP server.** The `hayabusa` server Claude Code is currently connected
  to predates the `rule_filter`/`output_format`/`max_results` params and the whole
  `get_hayabusa_rules` tool. Running `/mcp` did not pick up the change (the subprocess appears to
  be reused rather than restarted) — a full Claude Code restart is needed to confirm the new
  tools are live end-to-end through the MCP interface, not just via direct Python import.
- **No automated test suite.** `test_scan.py` is a manual smoke script, not `pytest`-based, and
  doesn't cover `get_hayabusa_rules`, error paths (missing file, missing Hayabusa binary, bad
  params), or the new `scan_evtx` params.
- **Cross-platform untested.** Everything has only run on Windows. `_find_hayabusa_binary()` and
  `scripts/download_hayabusa.py` have Linux/macOS branches written but never exercised.
- **No directory-scan test.** `scan_evtx` supports a directory of `.evtx` files (`-d` flag), but
  every test so far has used a single file.
- **`rule_filter` doesn't actually restrict which rules Hayabusa runs** — see Decisions. If a
  true "only load rules matching X" behavior is wanted, it would need to build a filtered rule
  directory (or use Hayabusa's `--include-tag`/`--include-category` flags) before invoking
  `json-timeline`.
- **No pagination beyond `max_results` truncation** — a caller can't fetch "the next N" findings
  or rules; every call re-scans/re-filters from scratch.
- **Global Claude Desktop config was not touched.** Early on we found `%APPDATA%\Claude\claude_desktop_config.json`
  is actually this app's own settings file, not an MCP registry — we deliberately used the
  project-level `.mcp.json` instead (see Decisions). If Claude Desktop (the separate classic app)
  integration is ever wanted, that's still unaddressed.

## Decisions we made and why

- **Low-level `mcp.server.Server` API, not `FastMCP`.** Originally scaffolded with `FastMCP` and
  `@server.tool()`, then rebuilt on `Server`/`@server.list_tools()`/`@server.call_tool()` per
  explicit request — this gives direct control over the JSON Schema `inputSchema` and the
  `TextContent` return type.
- **JSONL output (`-L`), not plain `-o` JSON.** Hayabusa's plain `-o file.json` writes multiple
  pretty-printed JSON objects concatenated with no separators — not valid JSON, not valid JSONL
  either. `-L` produces genuine one-object-per-line JSONL, which we parse line by line. Found via
  a real crash in testing (`json.JSONDecodeError: Extra data`).
- **`-b` (disable-abbreviations) is required.** Hayabusa abbreviates `informational` → `info` in
  the `Level` field by default. Our severity filter compares against the full word, so without
  `-b`, `info`-level findings were silently dropped even when `min_severity="informational"`
  (the lowest threshold, which should include everything). Found via a real discrepancy between
  Event Viewer's raw event count and our reported finding count.
- **Empty output file means zero findings, not an error.** Hayabusa writes a 0-byte file (not
  `"[]"`) when a scan finds no detections. `_run_scan_evtx` checks file size before attempting to
  parse.
- **Errors are returned as JSON payloads inside `TextContent`, not raised as MCP protocol
  errors.** Keeps the tool contract simple and predictable for a client — always get JSON back,
  distinguish failure via an `"error"` key rather than catching a transport-level exception.
- **`get_hayabusa_rules` results are cached in-process.** Parsing ~5,000 rule YAML files takes
  ~7 seconds; since rule files don't change while the server is running, caching after the first
  call is a reasonable simplification. (Tradeoff: won't reflect rule changes without a process
  restart.)
- **`rule_filter` filters findings after the scan, not which rules Hayabusa loads.** Hayabusa's
  CLI has no "run only rules matching this substring" flag — the closest native options
  (`--include-tag`, `--include-category`, etc.) work on structured tags/categories, not free-text
  substrings. Post-filtering the results by `RuleTitle` was the pragmatic fit for the literal
  request ("only run rules matching this string").
- **`output_format` defaults to `"summary"`.** A `"full"` finding carries large nested objects
  (`Details`, `ExtraFieldInfo`, full `CallTrace` strings) that bloat the response; most callers
  likely want the condensed view by default and can opt into `"full"` when needed.
- **`.mcp.json` (project-scoped Claude Code config), not `%APPDATA%\Claude\claude_desktop_config.json`.**
  That AppData file turned out to be live UI/preference state for this app itself (`coworkUserFilesPath`,
  pane layout, etc.), not an MCP server registry — editing it risked corrupting unrelated live
  settings for no benefit. `.mcp.json` is the standard, low-risk, project-scoped mechanism Claude
  Code's `/mcp` command actually reads.
- **Downloaded Hayabusa binary path is resolved by glob, not hardcoded.** The official release
  zip ships a version-suffixed binary name (`hayabusa-3.10.0-win-x64.exe`), not the generic
  `hayabusa.exe` originally assumed. `_find_hayabusa_binary()` checks the generic name first,
  then falls back to a glob, so it keeps working across Hayabusa version upgrades.
