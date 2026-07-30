# HANDOFF.md — continuing the work

_Last updated: 2026-07-30_

For the factual snapshot (what's wired, verified results), see `STATE.md`. This doc is the
narrative: what's done, what's missing, and what to do next.

## Where things stand

The three lifecycle guardrails work and are verified (see `STATE.md`):

- **`SessionStart`** warns on missing `jq`/`python3` and exits 0 (fail-open).
- **`PreToolUse` (`.*`)** blocks any tool call whose `file_path` matches a secret pattern
  (`.env`, `*.key`, `*.pem`, `secrets/`, `credentials/`) with exit 2 — verified against
  `config/.env` (blocked) and `rules/valid.yml` (allowed).
- **`PostToolUse` (`Write|Edit`)** logs every edit and validates any file under `rules/`,
  surfacing failures back to Claude with exit 2 — verified against all three fixtures.

## Missing pieces (the two module features not wired here)

The module brief lists five guardrails; two have **no script in this repo**. These are the next
work, not silently-dropped scope:

1. **Desktop notifications on completion.** Add a `Stop` (or `Notification`) hook to
   `.claude/settings.json` that fires when Claude finishes a turn. On Windows the notifier is
   PowerShell toast (`New-BurntToastNotification` if the module is installed, or a
   `Windows.UI.Notifications` snippet); keep it non-blocking (exit 0) so a notifier failure never
   stalls the session.
2. **Cost guardrails.** Add a hook that reads usage/turn cost and warns (or blocks) past a
   threshold. The mechanism depends on what the harness exposes on stdin to the relevant hook —
   confirm the available fields before wiring, and default to **warn-only** (exit 0) unless a
   hard budget stop is explicitly wanted.

## Suggested next steps

1. **Decide fail-open vs. fail-closed for cost guardrails.** Notifications should always be
   fail-open. Cost: warn-only by default; only exit 2 if the user wants a hard stop.
2. **Wire the `Stop` notification hook** first (lowest risk, most visible), then the cost hook.
3. **PowerShell port (optional).** The hooks currently need Git Bash + `jq` on `PATH`. A native
   PowerShell version (parse stdin JSON with `ConvertFrom-Json`) would make the repo run on a
   stock Windows box with no Git Bash. Trade-off: two script sets to maintain.
4. **Broaden the validator (optional).** `validate-rule.sh` checks two things (description +
   `attack.tNNNN`). The Module 5 `mcp-detection-kb` validator is richer (severity justification,
   concrete false positives, test evidence) — consider calling a shared Python validator from the
   `PostToolUse` hook instead of the minimal shell check, so both projects enforce one standard.

## Gotchas that will bite

- **Relative paths:** hook commands (`./scripts/…`) resolve from the **project root** — launching
  Claude Code from elsewhere makes the hooks "silently not run." Start from `detection-workflow/`.
- **`jq` dependency:** `check-sensitive.sh` and the inline `PostToolUse` command both need `jq`.
  Without it the sensitive-file block fails to extract the path — the prereq hook warns about this
  at `SessionStart`, so heed that warning.
- **Tactic vs. technique tags:** the validator requires an ATT&CK **technique** (`attack.t1059`),
  not just a tactic (`attack.execution`). `invalid.yml` fails for exactly this reason — it's a
  fixture, not a bug.
- **`.*` matcher on `PreToolUse`** runs the sensitive check on *every* tool call. Keep that script
  fast and side-effect-free.

## Housekeeping

- `hook-test.log` and `validation.log` are append-only demo artifacts — safe to truncate before a
  clean demo run. `test.txt` (`Hello, hooks!`) is scratch and can be deleted.
