# HANDOFF

Status snapshot of the Hayabusa MCP server as of 2026-07-15. See [CLAUDE.md](CLAUDE.md) for the
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

### Detection engineering knowledge base (new)

`server.py` also now exposes a small **Sigma rule + ATT&CK coverage knowledge base** as MCP
resources, separate from the Hayabusa-scanning tools above:

- **`detection://rules`** — JSON metadata (name, title, level, status, tags, `technique_ids`,
  file path) for all 6 curated Sigma rules under `rules/`.
- **`detection://rules/{rule_name}`** — raw YAML content of one rule, addressed by its file stem
  (e.g. `proc_creation_win_cmdkey_recon`).
- **`detection://rules/by-technique/{technique_id}`** — JSON list of rule metadata for rules
  tagged with a given ATT&CK technique (accepts `T1003.001` or `1003.001`, case-insensitive).
  Unmatched techniques return an empty list, not an error.
- **`detection://attack/techniques/{technique_id}`** — the ATT&CK technique's `name`,
  `description`, and `tactics` (from MITRE data), plus `detecting_rules` (our rules tagged with
  it) and a `coverage` verdict: `"gap"` (no matching rule), `"partial"` (matching rule(s) but all
  below medium severity), or `"covered"` (at least one medium+ severity rule). Unknown technique
  IDs raise `FileNotFoundError` → surfaced as an MCP error response.

`list_resources()` enumerates a concrete entry per rule and per technique we have tagged; the
templated forms (`{rule_name}`, `{technique_id}`) are also advertised via
`list_resource_templates()` for clients that construct URIs dynamically.

### Coverage analysis tools (new)

Two more tools layer analysis on top of the resource data above, rather than duplicating any of
its coverage logic:

- **`analyze_coverage`** — takes `technique_id` (e.g. `T1003.001`) *or* `tactic` (e.g.
  `credential-access` / `Credential Access`), not both. For a technique, returns the same
  covered/partial/gap verdict as the `detection://attack/techniques/{id}` resource. For a tactic,
  aggregates that verdict across every technique tagged with it: a `coverage_summary`
  (covered/partial/gap counts), a `gaps` list (technique id + name), and full per-technique detail.
  Reuses `_get_sigma_rules_by_technique` and `_assess_coverage` — no separate scoring logic.
- **`suggest_rule`** — takes `technique_id` (required) and `create_template` (optional bool,
  default `false`). If the technique is already `covered`, returns that with no suggestion. If
  it's a gap, searches Hayabusa's ~5,000 bundled rules for ones already tagged with that technique
  and ranks them by `(not-deprecated, severity, stable-status)` — deprecated rules are
  deprioritized *before* severity, so a maintained rule at the same level always wins (caught in
  testing: T1003.006/DCSync initially picked a `deprecated` generic credential-dumper rule over a
  `test`-status rule purpose-built for AD-replication abuse detection, purely because they tied on
  severity and the deprecated one came first in file-scan order). Returns `approach:
  "promote_existing"` with the ranked candidates, or `approach: "write_new"` if nothing exists
  anywhere. With `create_template=True`, writes a starter Sigma YAML into `rules/<category>/`,
  where `<category>` and the `logsource:`/`detection:` blocks are copied from the actual seeding
  Hayabusa rule's own YAML (not guessed from its file path — an earlier version of this guessed
  `process_creation` from folder heuristics and got a Security-log-sourced DCSync rule wrong; fixed
  to read the candidate's real `logsource` instead). Idempotent (won't overwrite an existing
  template file) and invalidates the in-memory Sigma rule cache on write so the new file is
  immediately visible to coverage queries.

Both tools were smoke-tested via direct Python import (`server._analyze_coverage(...)`,
`server._suggest_rule(...)`) covering: single-technique and tactic-wide `analyze_coverage`;
`suggest_rule` for an already-covered technique (T1003.001), a gap with strong Hayabusa candidates
(T1558.003/Kerberoasting), and a genuine gap with no candidates anywhere (T1675/ESXi
Administration Command, which is VMware-ESXi-specific and outside what Windows-EVTX-scoped
Hayabusa or our curated rules can see at all); template creation, idempotency on re-creation, and
cache-invalidation causing a freshly-created template to flip a technique's coverage verdict from
`gap` to `covered` on the next call. Not yet exercised through the live MCP tool-call interface —
same reconnect caveat as below.

The 6 sample rules (curated from a shallow clone of [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma),
which was deleted after copying — not kept as a subrepo) live under `rules/<category>/`:

| Rule | Technique | Tactic |
|---|---|---|
| `process_creation/proc_creation_win_hktl_empire_powershell_uac_bypass.yml` | T1548.002 | Privilege Escalation |
| `process_creation/proc_creation_win_cmdkey_recon.yml` | T1003.005 | Credential Access |
| `powershell/posh_pc_downgrade_attack.yml` | T1059.001 | Execution |
| `registry/registry_set_asep_reg_keys_modification_common.yml` | T1547.001 | Persistence |
| `process_access/proc_access_win_lsass_memdump.yml` | T1003.001 | Credential Access |
| `create_remote_thread/create_remote_thread_win_hktl_cobaltstrike.yml` | T1055.001 | Privilege Escalation |

Supporting pieces:

- [scripts/download_hayabusa.py](scripts/download_hayabusa.py) — downloads the latest Hayabusa
  release for the current OS/arch from GitHub and extracts it to `./hayabusa/`. Already run once;
  `./hayabusa/` contains the v3.10.0 Windows x64 binary, `config/`, and `rules/`.
- [scripts/download_attack_data.py](scripts/download_attack_data.py) — downloads the full MITRE
  ATT&CK Enterprise STIX bundle (~50MB) once and extracts a trimmed technique index (id, name,
  description, tactics — ~1.4MB, 858 techniques) to `attack/techniques.json`. Already run once.
- [test_scan.py](test_scan.py) — manual smoke test: imports `server` directly and calls
  `scan_evtx` against a real sample.
- Resource smoke testing so far has been ad-hoc (a scratch script exercising every
  `detection://...` URI, not committed to the repo) — see **What's left to do** below.
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
  `get_hayabusa_rules` tool — and now also predates `analyze_coverage` and `suggest_rule` entirely.
  Running `/mcp` did not pick up the change (the subprocess appears to be reused rather than
  restarted) — a full Claude Code restart is needed to confirm the new tools are live end-to-end
  through the MCP interface, not just via direct Python import.
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
- **No automated smoke test for the resources.** The `detection://...` resource endpoints were
  verified with an ad-hoc scratch script (list all resources/templates, read each URI shape,
  confirm error paths), not a committed `pytest`/script-based test. Worth promoting into a
  `test_resources.py` alongside `test_scan.py` if this project keeps growing.
- **Only 6 Sigma rules, so ATT&CK coverage is mostly gaps.** `attack/techniques.json` has 858
  MITRE techniques; only 6 have any rule at all. That's expected for a curated sample set, not a
  bug, but worth remembering when demoing `detection://attack/techniques/{id}` against an
  arbitrary technique — most will legitimately come back `"gap"`.
- **Real gaps identified via `analyze_coverage`/`suggest_rule` are still unresolved.** Credential
  Access tactic coverage is 2/80 covered using only our curated rules (Kerberoasting, DCSync,
  Golden/Silver Ticket, password spraying, credential stores, AiTM, etc. are all gaps in `rules/`
  even where Hayabusa's bundled set has good candidates to promote — e.g. Kerberoasting has 4+
  matching Hayabusa rules). T1675 (ESXi Administration Command) is a full gap with **no** Hayabusa
  candidate either, since it's VMware-ESXi-specific and outside what a Windows-EVTX tool can see;
  real coverage there would need ESXi host-log ingestion (`hostd.log`, vCenter audit events), not
  a Sigma rule against EVTX. No templates have actually been committed to `rules/` yet — the
  DCSync template created during `suggest_rule` testing was deleted afterward as test cleanup.
- **`attack/techniques.json` is a generated artifact, not yet decided whether to commit or
  gitignore.** It's derived entirely from `scripts/download_attack_data.py` + the public MITRE
  STIX bundle, same relationship `./hayabusa/` has to `download_hayabusa.py`. `./hayabusa/` isn't
  committed (binary + huge rule set); `attack/techniques.json` is much smaller (~1.4MB) and static
  enough that committing it may be more convenient than requiring a download step. Not yet decided.

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
- **Sample Sigma rules were curated by hand from a shallow clone of SigmaHQ/sigma, then the
  clone was deleted.** Rather than vendoring the whole upstream repo (thousands of rules across
  every log source) or adding it as a git submodule, we `git clone --depth 1`'d it once, picked 6
  Windows-scoped rules covering distinct, well-known ATT&CK techniques (UAC bypass, credential
  recon, PowerShell downgrade, registry Run key persistence, LSASS dumping, Cobalt Strike
  injection), copied just those files into `rules/`, and removed the 48MB clone. Keeps the repo
  small; `rules/` is the only Sigma content actually version-controlled here.
- **ATT&CK technique IDs are derived from Sigma tags at read time, not stored in a separate
  mapping file.** The original ask mentioned a `mappings/` directory, but since every Sigma rule
  already encodes its technique(s) as an `attack.tXXXX` tag, parsing that tag with a regex
  (`TECHNIQUE_TAG_RE` in `server.py`) avoids a second data source that could drift out of sync
  with the rules themselves.
- **ATT&CK technique metadata (name/description/tactics) is pre-extracted into a small local
  JSON file, not fetched live per request.** The public MITRE STIX bundle is ~50MB of the full
  ATT&CK knowledge base (groups, software, mitigations, relationships, etc.); we only need
  technique name/description/tactics, so `scripts/download_attack_data.py` downloads it once and
  writes a ~1.4MB `attack/techniques.json` (858 techniques) that the server loads and caches in
  memory, same pattern as the Hayabusa/Sigma rule caches.
- **Coverage assessment uses a severity threshold, not rule count.** A technique with only a
  `low`-level rule matching is still meaningfully under-detected, so `_assess_coverage()` requires
  at least one rule at `COVERED_MIN_LEVEL` ("medium") or above to count as `"covered"`; anything
  with matching rule(s) below that bar is `"partial"`, and zero matches is `"gap"`. Simple and
  transparent over a weighted scoring scheme, which felt like premature sophistication for 6 rules.
- **`suggest_rule`'s candidate ranking deprioritizes `deprecated` status ahead of severity.**
  Originally sorted by severity level alone; testing against T1003.006 (DCSync) surfaced a real bug
  where a `deprecated`, only-loosely-related rule ("Credential Dumping Tools Service Execution")
  tied on severity with, and beat by list order, a `test`-status rule purpose-built for DCSync
  ("Active Directory Replication from Non Machine Account"). Fixed by ranking
  `(not-deprecated, level, is_stable)` so status is checked before severity.
- **Generated rule templates copy `logsource`/`detection` from the real seeding rule, not a
  file-path guess.** The first version inferred the template's category/logsource by pattern-
  matching the Hayabusa candidate's file path against our five known `rules/` subfolders, which
  silently mis-categorized a Security-log-sourced DCSync detection as `process_creation`. Fixed to
  read the candidate rule's actual `logsource:` block and derive both the folder and the
  `logsource` field from it — which also means new category folders (e.g. `rules/security/`) can
  appear organically instead of being forced into the original five.
