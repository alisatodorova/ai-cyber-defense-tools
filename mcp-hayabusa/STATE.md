# STATE

Last updated: 2026-07-14. Read this first when resuming work — it's the "where exactly did we
leave off" snapshot. For the full narrative (what was built, how to use it, and the reasoning
behind each decision) see [HANDOFF.md](HANDOFF.md); the standing project brief is [CLAUDE.md](CLAUDE.md).

## Current status

`server.py` implements both planned tools (`scan_evtx`, `get_hayabusa_rules`) and both have been
verified working **by importing `server` directly in Python** (`test_scan.py`, plus ad-hoc calls
to `call_tool(...)`). They have **not** been verified working through the live MCP connection.

## Immediate next step

The `hayabusa` MCP server Claude Code is connected to is running stale code from before
`rule_filter`/`output_format`/`max_results` were added to `scan_evtx` and before
`get_hayabusa_rules` existed at all. Running `/mcp` did not refresh it (the subprocess seems to
be reused, not restarted). **Next action: fully quit and reopen Claude Code**, then run `/mcp`
again and confirm via `ToolSearch`/tool call that `mcp__hayabusa__get_hayabusa_rules` exists and
`mcp__hayabusa__scan_evtx`'s schema includes all four optional params. Re-run the example calls
in HANDOFF.md's "How to use it" section through the actual MCP tool interface once reconnected,
not just via direct import, to close this out.

## Key facts to avoid re-deriving

- Hayabusa binary lives at `./hayabusa/hayabusa-3.10.0-win-x64.exe` (version-suffixed; found via
  glob in `_find_hayabusa_binary()`, not a hardcoded name).
- Rule files live at `./hayabusa/rules/{hayabusa,sigma}/**/*.yml` (~4,961 `.yml` files total;
  `./hayabusa/rules/config/` holds non-rule field-mapping data, already excluded).
- Sample test file: `test_data/UACME_59_Sysmon.evtx` — real Sysmon telemetry, 8 findings across
  3 rules when scanned unfiltered (`Proc Access` x5, `Proc Exec` x2, `New Process Created Via
  Taskmgr.EXE` x1 — the last one is the actual UAC-bypass technique the sample demonstrates).
- MITRE tactic tags are hyphenated (`credential-access`), not underscored or spaced — matters
  for `keyword`/`rule_filter` since those are plain substring matches.
- `.mcp.json` in the project root registers this server for Claude Code; `%APPDATA%\Claude\claude_desktop_config.json`
  is unrelated app UI state, not an MCP registry — do not edit it for this purpose.

## Open items (see HANDOFF.md "What's left to do" for the full list)

- No automated (pytest) test suite yet.
- Linux/macOS code paths written but never run.
- No test exercising `scan_evtx` against a directory of `.evtx` files (only single-file tested).
- `rule_filter` filters findings after scanning; it doesn't restrict which Hayabusa rules
  actually execute (no CLI flag for arbitrary substring rule selection exists).
