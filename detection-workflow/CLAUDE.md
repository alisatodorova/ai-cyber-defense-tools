# CLAUDE.md — detection-workflow

Project-level guidance for Claude Code working in this repo. (User-global rules in
`~/.claude/CLAUDE.md` also apply — e.g. always show command/script output in chat and use tables
where suitable.)

## What this project is

A demonstration of **Claude Code hooks** (AI Cyber Defense Ops, Module 7) that enforce
detection-engineering guardrails automatically across the agent lifecycle. The wiring lives in
`.claude/settings.json`; the logic lives in three POSIX-shell scripts under `scripts/`.

- **`.claude/settings.json`** — the hook registrations (the core deliverable).
- **`scripts/check-prereqs.sh`** — `SessionStart`: warn on missing `jq`/`python3`, exit 0.
- **`scripts/check-sensitive.sh`** — `PreToolUse`: block writes to secret files, exit 2.
- **`scripts/validate-rule.sh`** — `PostToolUse`: validate a Sigma-style rule, exit 2 on failure.
- **`rules/`** — fixtures: `valid.yml` (passes), `invalid.yml` / `test-rule.yml` (fail).
- **`hook-test.log`** / **`validation.log`** — append-only logs written by the hooks.

## The hook wiring (`.claude/settings.json`)

| Event | Matcher | Command | Contract |
|---|---|---|---|
| `SessionStart` | — | `./scripts/check-prereqs.sh` | Warn-only. Always exit 0. |
| `PreToolUse` | `.*` | `./scripts/check-sensitive.sh` | Exit 0 = allow, **exit 2 = block** the tool call. |
| `PostToolUse` | `Write\|Edit` | `echo 'File modified' >> hook-test.log` | Trivial edit logger. |
| `PostToolUse` | `Write\|Edit` | inline `bash -c` → `scripts/validate-rule.sh` | Runs only when the edited `file_path` contains `rules`; appends output to `validation.log`; **exit 2** on failure surfaces the message back to Claude. |

## Hook contract (how the harness talks to a hook)

- **Input:** the tool call arrives as **JSON on stdin**. Extract the path with
  `jq -r '.tool_input.file_path // empty'`. Tools like `Bash` have no `file_path` — handle the
  empty case (allow / no-op), don't crash.
- **Output / exit codes are the control flow:**
  - `PreToolUse` **exit 2 → the tool call is blocked**; stderr text explains why.
  - `PostToolUse` **exit 2 → the failure text is fed back to Claude** for in-loop correction.
  - **exit 0 → proceed.** Use exit 0 for warn-only guards (`check-prereqs.sh`).
- Hook `command` paths are **relative to the project root** — launch Claude Code from
  `detection-workflow/`.

## Validation rules (`validate-rule.sh`)

A rule file must have:
1. a `description:` field, and
2. at least one MITRE ATT&CK **technique** tag matching `attack.t[0-9]{3,}` (case-insensitive).

Tactic-only tags (`attack.execution`) do **not** satisfy rule 2 — a technique ID is required.
`set -euo pipefail`; one message per problem; `OK: <file>` + exit 0 when clean.

## Conventions

- **Fail-closed on secrets, fail-open on tooling.** `check-sensitive.sh` blocks hard (exit 2);
  `check-prereqs.sh` only warns (exit 0). The exit code is the policy — choose it deliberately.
- Treat the sensitive-file block as a **security boundary enforced by the harness**, independent
  of anything the model was told to do (prompt-injection defense). Don't weaken it to make an
  edit convenient.
- Keep hooks **fast and side-effect-light** — they run on every matching action.
- Logs (`hook-test.log`, `validation.log`) are append-only artifacts of the demo; safe to clear.

## Environment (this machine — Windows)

- Hooks are **Bash + `jq`**. Both resolve via Git Bash / winget on `PATH` here (`jq` and
  `python3` confirmed present). A native **PowerShell** port would remove the Git Bash dependency
  — not done yet.
- `check-prereqs.sh` also checks `python3`, though no current script needs it — it's a
  placeholder for future Python-based validators.

## Not yet implemented (module features with no script here)

- **Desktop notifications on completion** — would be a `Stop` / `Notification` hook. Absent.
- **Cost guardrails** — a budget-aware hook. Absent.

See `HANDOFF.md` for how to add these next.
