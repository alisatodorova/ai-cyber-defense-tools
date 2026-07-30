# STATE.md — point-in-time snapshot

_Last updated: 2026-07-30_

A factual snapshot of the environment and repo. For "what to do next," see `HANDOFF.md`.

## Environment

| Component | State | Detail |
|---|---|---|
| Shell for hooks | **Bash (Git Bash)** | Hooks are POSIX shell; launched from project root |
| `jq` | **Present** | `…/WinGet/Packages/jqlang.jq…/jq` — parses tool-call JSON |
| `python3` | **Present** | `…/WindowsApps/python3` — checked by prereq hook, unused by scripts |
| PowerShell | 5.1 only | Hooks do not use it (no PowerShell port yet) |
| OS | Windows 11 Pro | — |

## Hooks wired (`.claude/settings.json`)

| Event | Matcher | Command | Status |
|---|---|---|---|
| `SessionStart` | — | `./scripts/check-prereqs.sh` | ✅ warn-only, exit 0 |
| `PreToolUse` | `.*` | `./scripts/check-sensitive.sh` | ✅ blocks secrets, exit 2 |
| `PostToolUse` | `Write\|Edit` | `echo 'File modified' >> hook-test.log` | ✅ edit logger |
| `PostToolUse` | `Write\|Edit` | inline `bash -c` → `validate-rule.sh` | ✅ validates rules/*, exit 2 on fail |

## Module features — coverage

| Feature (from module brief) | Implemented here | Mechanism |
|---|---|---|
| Automatic validation on every file save | ✅ | `PostToolUse` → `validate-rule.sh`, feedback to Claude |
| Protection for sensitive files (blocks w/ message) | ✅ | `PreToolUse` → `check-sensitive.sh`, exit 2 |
| Prerequisite checks on startup | ✅ | `SessionStart` → `check-prereqs.sh` |
| Desktop notifications on completion | ❌ **not wired** | would be a `Stop`/`Notification` hook |
| Cost guardrails | ❌ **not wired** | would be a budget-aware hook |

## Scripts

| Path | Purpose | Exit contract |
|---|---|---|
| `scripts/check-prereqs.sh` | Warn on missing `jq`/`python3` | Always 0 (fail-open) |
| `scripts/check-sensitive.sh` | Block writes to `.env`/`*.key`/`*.pem`/`secrets/`/`credentials/` | 0 allow, 2 block |
| `scripts/validate-rule.sh` | Require `description` + `attack.tNNNN` | 0 pass, 2 fail |

## Rule fixtures — validator results (verified 2026-07-30)

| File | Content | Result |
|---|---|---|
| `rules/valid.yml` | title + description + `attack.t1059.001` | ✅ `OK: rules/valid.yml` (exit 0) |
| `rules/invalid.yml` | title + tactic-only tag | ❌ missing description; no `attack.t*` (exit 2) |
| `rules/test-rule.yml` | title only | ❌ missing description; no `attack.t*` (exit 2) |

## Sensitive-file block — verified 2026-07-30

| Input `file_path` | Result |
|---|---|
| `config/.env` | 🚫 BLOCKED (exit 2) |
| `rules/valid.yml` | ✅ allowed (exit 0) |
| (no `file_path`, e.g. Bash) | ✅ allowed (exit 0) |

## Logs

| File | Content |
|---|---|
| `hook-test.log` | ~22 `File modified` lines (append-only edit log) |
| `validation.log` | Prior validator failures (missing description / no `attack.t*`) |
| `test.txt` | `Hello, hooks!` — scratch file from testing PostToolUse |

## Docs

| File | Status |
|---|---|
| `README.md` | ✅ created (GitHub-facing) |
| `CLAUDE.md` | ✅ created (standing brief) |
| `HANDOFF.md` / `STATE.md` | ✅ created |
