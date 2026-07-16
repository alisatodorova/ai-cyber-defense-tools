# AI Cyber Defense Tools

A collection of practical security tools built while completing [**AI Cyber Defense Ops**](https://www.justhacking.com/course/ai-cyber-defense-ops/) (Just Hacking Training, instructor Anton Ovrutsky) - a hands-on course on using Claude to build real blue-team tooling: wrapping security CLIs as MCP servers, codifying detection methodology, automating repeatable analyst workflows, and correlating threat intel across sources.

Each tool below is a self-contained project with its own README, architecture notes, and a documented build history (including the debugging and design decisions along the way, not just the finished code).

## Why this repo

Most "I used AI" portfolio pieces show a prompt and a screenshot. Mine don't. Each tool here is a real, runnable piece of software solving an actual defensive-security problem - the kind of task a detection engineer, purple teamer, or IR analyst does by hand today. What I'm demonstrating is the combination that matters for an AI Security role: I understand the security domain well enough to know what's worth building, and I know how to use Claude to build it correctly, safely, and quickly, including catching the AI's mistakes along the way.

## Tools

| Tool | What it does | Course module | Stack |
|---|---|---|---|
| [`mcp-detection-kb`](mcp-detection-kb/) | A detection-engineering knowledge base of Sigma and YARA-X rules built to a mechanically-enforced quality standard rather than ad hoc review - a Claude Code skill (`detection-engineering`) codifies the required elements of every rule (ATT&CK tag, justified severity, concrete false positives, test evidence, naming convention), backed by a `validate-rule.py` script that checks compliance and prints a pass/fail JSON report | Module 5 - Skills: Codifying Methodology | Sigma, YARA-X, Python (validation scripts), Claude Code skills |
| [`mcp-hayabusa`](mcp-hayabusa/) | MCP server wrapping the [Hayabusa](https://github.com/Yamato-Security/hayabusa) EVTX threat-hunting CLI - exposes `scan_evtx` and `get_hayabusa_rules` as structured-JSON tools an LLM client can call directly against Windows event logs. Also doubles as a detection engineering knowledge base: curated Sigma rules and MITRE ATT&CK coverage exposed as browsable resources, plus `analyze_coverage` (tactic/technique-level covered vs. gap reporting) and `suggest_rule` (finds a promotable candidate in Hayabusa's bundled rule set, or scaffolds a new Sigma rule template, for a coverage gap) | Module 3 - MCP: Wrapping Security CLIs and Module 4: MCP - Detection Knowledge Bases | Python, MCP SDK, Hayabusa (Rust CLI, subprocess), Claude Code resources |
| [`sysmon-parser`](sysmon-parser/) | Dependency-free CLI that extracts, filters, and triages Sysmon process-creation (Event ID 1) telemetry from raw XML into JSON/JSONL/CSV, with summary stats for quick hunting | Module 2 - Building Your First Security Tool | Python (stdlib only) |

*(More tools land here as I work through the rest of the course)*

## Skills map

**Security fundamentals demonstrated:**
- Windows event log / EVTX and Sysmon telemetry analysis
- Sigma-rule-based detection engineering, MITRE ATT&CK tagging conventions
- Process-creation triage: parent/child chains, integrity levels, command-line obfuscation (base64 `-Enc`, LOLBAS patterns)
- Threat-hunting workflows: filter → correlate → triage → drill down
- Turning a detection ruleset into a queryable coverage model (technique → rules → covered/partial/gap) and using it to drive concrete next steps (promote an existing rule vs. author a new one)
- YARA-X rule authoring (atom-quality/performance tradeoffs, distinguishing an inherent detection-technique limitation from an actual defect) alongside Sigma

**AI/agentic engineering demonstrated:**
- Building MCP servers that wrap existing CLI tools rather than reimplementing their logic - invocation, output translation, and error handling as the value-add
- Designing structured, predictable tool contracts (explicit JSON error codes, not opaque exceptions) so an LLM client can reason about failures
- Treating external tools/binaries as an untrusted boundary - failing fast and explicitly instead of silently degrading
- Real debugging discipline when working with Claude: e.g. tracing a silent data-loss bug back to an undocumented CLI flag behavior (Hayabusa abbreviating `informational` → `info`) by comparing against ground truth, not trusting first-pass output
- Building analysis tools on top of existing resource data instead of duplicating it, and catching real bugs in ranking/inference heuristics (e.g. a `deprecated` rule outranking a purpose-built one, or a generated rule template's log source being guessed from a file path instead of read from the source rule) through actual testing
- Codifying a written methodology (what makes a detection rule "done") as a Claude Code skill plus a companion script that checks it mechanically, so compliance doesn't depend on a reviewer remembering to ask the right questions every time

## How this maps to an AI Security role

These projects are small versions of a pattern that scales directly to production AI-assisted security tooling: take an existing tool or workflow a SOC/IR team already trusts, wrap it so an LLM agent can drive it safely, and get the contract right - structured outputs, explicit failure modes, no silent data loss. That's the same shape of work as building agent-based security automation, AI-assisted triage copilots, or detection-knowledge-base tooling inside a security product or SOC.

## Repo layout

Each tool lives in its own top-level folder with its own `README.md` (usage, architecture, skills demonstrated), `CLAUDE.md` (standing project brief), and `HANDOFF.md`/`STATE.md` (build narrative and decision log - kept intentionally, as evidence of process, not just output).

```
ai-cyber-defense-tools/
├── README.md                 <- this file
├── mcp-hayabusa/
│   ├── README.md
│   └── ...
├── sysmon-parser/
│   ├── README.md
│   └── ...
└── ...
```
