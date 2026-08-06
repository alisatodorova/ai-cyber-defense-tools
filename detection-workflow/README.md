# detection-workflow — hooks that enforce detection-engineering guardrails automatically

> **AI Cyber Defense Ops — Module 7: Hooks (Automation Triggers)**
> Built as part of [module 7, "Hooks (Automation Triggers)"](https://www.justhacking.com/course/ai-cyber-defense-ops/), from Just Hacking Training's *AI Cyber Defense Ops* course.


A set of **Claude Code hooks** that turn a detection-rule repo into a self-policing workspace:
every time a rule file is written, it's validated; every time a tool tries to touch a sensitive
file, it's blocked; and every session checks its own prerequisites before work starts. The
guardrails run *deterministically, on every action* — they don't depend on Claude (or a human)
remembering to run a linter or avoid a secret.

The point of the module isn't "a shell script that lints YAML." It's wiring policy into the
**lifecycle of the agent itself** — `SessionStart`, `PreToolUse`, `PostToolUse` — so the rules
are enforced by the harness, not by good intentions. A `PostToolUse` validation failure exits
non-zero and the error text is fed *back to Claude*, so a bad rule is caught and corrected
in-loop, not at review time.

## What it does

Three hooks, wired in [`.claude/settings.json`](.claude/settings.json):

| Event | Hook | Effect |
|---|---|---|
| **SessionStart** | [`scripts/check-prereqs.sh`](scripts/check-prereqs.sh) | Warns (never blocks) if `jq` or `python3` is missing, so a broken environment is visible at startup instead of mid-task. |
| **PreToolUse** (`.*`) | [`scripts/check-sensitive.sh`](scripts/check-sensitive.sh) | Reads the tool call on stdin, extracts `tool_input.file_path`, and **blocks** (exit 2) any write to `.env`, `*.key`, `*.pem`, `secrets/`, or `credentials/` — before the write happens. |
| **PostToolUse** (`Write\|Edit`) | inline logger + [`scripts/validate-rule.sh`](scripts/validate-rule.sh) | Logs the edit to `hook-test.log`; if the edited path contains `rules`, validates it and, on failure, exits 2 so the error is surfaced back to Claude and appended to `validation.log`. |

### The pieces in action

**Validation on save** — the validator requires a `description` field and at least one MITRE
ATT&CK technique tag (`attack.tNNNN`):

```
$ scripts/validate-rule.sh rules/valid.yml
OK: rules/valid.yml                       # exit 0

$ scripts/validate-rule.sh rules/invalid.yml
Missing required field: description        # exit 2 -> fed back to Claude
tags must contain at least one attack.t* entry
```

Because it's a `PostToolUse` hook with a non-zero exit, Claude *sees* those two lines the moment
it writes a bad rule and can fix them without a human in the loop. `rules/valid.yml` passes;
`rules/invalid.yml` and `rules/test-rule.yml` are deliberately broken fixtures that fail.

**Sensitive-file protection** — a `PreToolUse` hook inspects every tool call and refuses the
ones that would touch secrets:

```
$ printf '{"tool_input":{"file_path":"config/.env"}}' | scripts/check-sensitive.sh
BLOCKED: 'config/.env' matches a sensitive-file pattern (.env, *.key, *.pem, secrets/,
credentials/). Refusing tool call.        # exit 2 -> tool call never runs
```

A normal path (`rules/valid.yml`) returns exit 0 and the tool proceeds. Tools with no
`file_path` (e.g. `Bash`) pass through untouched.

**Prerequisite check on startup** — `SessionStart` warns about a missing `jq`/`python3` but
always exits 0, so a missing dependency is *surfaced* without refusing to start the session.

## Why hooks (not a Makefile or a skill)

- **Deterministic & unskippable** — the harness runs the hook on *every* matching action. There
  is no "forgot to run the linter" failure mode.
- **In-loop feedback** — a `PostToolUse` non-zero exit returns the message to Claude, so a bad
  rule is corrected during generation, not flagged in review.
- **Fail-*closed* where it matters, fail-*open* where it doesn't** — secret access is blocked
  hard (exit 2); a missing dev tool only warns (exit 0). The exit code *is* the policy.
- **Defense against prompt injection / mistakes** — the sensitive-file block is enforced by the
  harness regardless of what the model was told to do, so a stray instruction to read a `.env`
  can't get through.

## Repo layout

```
detection-workflow/
├── .claude/settings.json     <- the hook wiring (SessionStart / PreToolUse / PostToolUse)
├── scripts/
│   ├── check-prereqs.sh      <- SessionStart: warn on missing jq/python3 (exit 0)
│   ├── check-sensitive.sh    <- PreToolUse: block writes to secrets (exit 2)
│   └── validate-rule.sh      <- PostToolUse: require description + attack.tNNNN (exit 2)
├── rules/
│   ├── valid.yml             <- passes validation (fixture)
│   ├── invalid.yml           <- fails: no description, no attack.t* (fixture)
│   └── test-rule.yml         <- fails: title only (fixture)
├── hook-test.log             <- append-only PostToolUse edit log
├── validation.log            <- append-only validator output
├── CLAUDE.md                 <- standing project brief
└── HANDOFF.md / STATE.md     <- build narrative + point-in-time state
```

## Setup

1. **Bash + `jq`** on `PATH` (the hooks are POSIX shell and parse the tool-call JSON with `jq`).
   On Windows, Git Bash provides `bash`; `jq` via winget/`scoop`. `python3` is checked by the
   prereq hook but not required by the current scripts.
2. **Open the folder in Claude Code.** `.claude/settings.json` registers the hooks
   automatically; the `SessionStart` prereq check runs on open.
3. **Try it** — write a rule to `rules/` and watch `validation.log`; attempt to write a `.env`
   and watch the `PreToolUse` block fire.

> Hook commands are relative to the project root (e.g. `./scripts/check-prereqs.sh`), so launch
> Claude Code from the `detection-workflow/` directory.

## Skills demonstrated

**Security:**
- Detection-engineering quality gates as code: a rule isn't "done" without a `description` and a
  MITRE ATT&CK technique tag, enforced mechanically rather than by review
- Secret-handling / data-loss prevention: hard-blocking any tool write to `.env`, `*.key`,
  `*.pem`, `secrets/`, `credentials/` at the tool boundary
- Fail-open vs. fail-closed as a deliberate security decision (warn on missing tooling, block on
  secret access)

**AI / agentic engineering:**
- Wiring policy into the agent lifecycle with Claude Code hooks (`SessionStart` / `PreToolUse` /
  `PostToolUse`) and matchers (`.*`, `Write|Edit`)
- Using hook **exit codes as control flow**: exit 2 blocks a `PreToolUse` call and surfaces
  `PostToolUse` failures back to the model for in-loop correction
- Parsing the tool-call contract on stdin (`jq -r '.tool_input.file_path'`) and handling the
  no-`file_path` case (e.g. `Bash`) so the guard degrades safely
- Defense-in-depth against prompt injection: the harness enforces the guard regardless of the
  model's instructions

## Build notes 
- **Cross-platform caveat:** the hooks are Bash + `jq`. On Windows they need Git Bash on `PATH`;
  a native PowerShell port would make them shell-agnostic. Noted, not done.
