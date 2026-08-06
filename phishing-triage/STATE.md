# STATE — phishing-triage

Snapshot of exactly where this project stands. For the fuller narrative see
[HANDOFF.md](HANDOFF.md).

## Status: complete and verified

All components built and passing. Course capstone; new domain (email) composing five Claude
Code mechanisms + the report/artifact deliverable.

## What works (verified)

- `python test_analyze.py` → **9/9 pass**. Sample verdicts: benign `0`, credential-phish `19`,
  malware-attachment `7`, bulgarian-phish `20`, real Google phish `7`, real Econt phish `10`;
  plus regression checks (legit `.bg` bank not mis-flagged, real samples PII-scrubbed, no
  network imports).
- `python report.py <eml> <out.html>` → writes all three reports; each renders correctly
  (verdict banner, reasons, auth grid, defanged IOC table, hops, ATT&CK chips) and passes
  `validate-report.py` (verdict + ATT&CK + hash present, **no fanged URL leak**).
- `server.py` imports; `analyze_email`, `defang_iocs`, `generate_report`, and the
  `phishing://indicators` resource all exercised via the async handlers.
- `check-no-detonation.sh` hook: blocks `WebFetch` and `curl …` (exit 2), allows normal
  commands and substrings like `curly` (exit 0).

## File inventory

- Engine: `analyze.py`, `report.py`, `indicators.json`
- MCP: `server.py`, `.mcp.json`, `requirements.txt`
- Tests: `test_analyze.py`
- Samples: synthetic `samples/{benign-newsletter,credential-phish,malware-attachment,credential-phish-bg}.eml`
  + real (sanitized) `samples/real-world/{google-cloud-storage-phish,econt-parcel-phish}.eml`
- Reports (committed demo artifacts): `reports/{…}.html` + `.json` for the real-world ones
- Command: `.claude/commands/triage-email.md`
- Skill: `.claude/skills/phishing-triage/SKILL.md` + `scripts/validate-report.py`
- Hook: `.claude/settings.json` + `scripts/check-no-detonation.sh`
- Persona: `personas/soc-analyst.md` + `soc-analyst-example.md`
- Docs: `README.md`, `CLAUDE.md`, `HANDOFF.md`, `STATE.md`


## Known limitations (see README)

- Verdict weights are heuristics tuned to the samples, not a trained classifier.
- SPF/DKIM/DMARC are read from the `Authentication-Results` header, not re-verified.
- Static analysis only — no archive unpacking, redirect following, or HTML rendering.
- Hook is Bash + jq (Git Bash); no PowerShell port yet.
