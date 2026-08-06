# Handoff

_For the next session / analyst picking this up. Pair with `state.md` (current status) and `CLAUDE.md` (workflow spec)._

## What this project is
Repeatable workflows for complex security analysis: (1) threat-intel ingestion →
TTPs + simulation plan, (2) multi-source investigation correlating endpoint and
cloud logs. See `CLAUDE.md` for the authoritative workflow + file conventions.

## Where things are
- **Outputs:** everything lands in `analysis/`.
- **Sample logs:** `logs/windows/` (endpoint), `logs/cloud/` (cloud). Synthetic — see `logs/README.md`.
- **Subagents:** `.claude/agents/endpoint-analyst.md`, `.claude/agents/cloud-analyst.md`.
- **Skill/command:** `/ingest-ti <url>` for the TI workflow.

## How to run the multi-source investigation
1. `endpoint-analyst` on `logs/windows/` → save to `analysis/endpoint.md`.
2. `cloud-analyst` on `logs/cloud/` → save to `analysis/cloud.md`.
3. Correlate both note files → `analysis/correlation.md`
   (timeline alignment, user + IP correlation, attack chain, confidence, gaps, containment).

## How to run TI ingestion
`/ingest-ti <report-url>` → `analysis/ti-<date>-<campaign>.md`.
Extraction is `defuddle parse "$url" --md`; **this host lacks `defuddle`/`npx`**,
so fall back to `WebFetch` for page content.

## Known limitations
- **Safeguard flag:** the `endpoint-analyst` subagent aborted once on an automated
  cyber-safeguard false positive. This is legitimate defensive IR — if it recurs,
  run that analysis inline; output format is identical.
- **Windows host / PowerShell primary shell.** Bash tool is available for POSIX.
- **Show results in chat** (tables for tabular data) per global instructions — not just file pointers.

## Open thread to resolve
The 02:11 cloud sign-in precedes the on-prem NTDS dump by ~7h, so its credential
likely came from the 07-15 AdaptixC2 foothold, not NTDS. `itadmin`'s compromise
point is also unseen (cloud-only). Both need gap-filling logs — see
`analysis/correlation.md` §6.

## Reasonable next actions
- Formal incident report (Word/PDF) from the `analysis/` set.
- `/correlate` command to automate the fan-out + merge.
- Add more sample scenarios / real log ingestion to harden the workflow.
