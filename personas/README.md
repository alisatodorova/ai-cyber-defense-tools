# personas — system prompts that turn Claude Code into a specific security role

> Built as part of [module 11, "System Prompts for Security Personas"](https://www.justhacking.com/course/ai-cyber-defense-ops/), from Just Hacking Training's *AI Cyber Defense Ops* course.

Three composable system prompts that constrain Claude Code into a specific
security-analyst mindset — a threat hunter, an incident responder, and a
detection engineer — each with its own priorities, default behaviors, hard
constraints, and enforced output format. No new tooling here: the point of
this module is that a well-written system prompt is itself a piece of
engineering, and a persona meant to be trusted on a real incident needs the
same rigor as code — explicit constraints, a fixed contract, and evidence
that it actually behaves as designed.

## Why personas, not just "be a threat hunter" in the chat

A one-line instruction typed into a conversation gets diluted or forgotten
after a few turns. A system prompt loaded via `--append-system-prompt-file`
holds for the entire session and can encode things a casual instruction
can't: hard "never do X" constraints, a fixed output contract, and default
behaviors that fire on *every* response without the user having to ask again
each time.

## The personas

| Persona | Mindset | Hard constraints | Output contract |
|---|---|---|---|
| [`threat-hunter`](personas/threat-hunter.md) | Proactive, hypothesis-driven — hunt for what automated detections missed | Never treats a hypothesis as confirmed without evidence; never suggests changing the live environment; never suggests destroying evidence | Hypothesis → Evidence → Pivots → Conclusion/Next Hypothesis |
| [`ir-responder`](personas/ir-responder.md) | Reactive, evidence-preserving — the host in scope may be evidence | Never suggests host-modifying actions (kill/reboot/reset/reinstall) unless the user explicitly says "containment phase"; never suggests clearing logs or running remediating AV scans; every claim labeled observed vs. inferred | TL;DR (exec) → Timeline table → Key findings → IOCs table → Open questions/gaps → Recommended next steps |
| [`detection-engineer`](personas/detection-engineer.md) | Skeptical rule author — distrusts every rule it just wrote | Never hand-waves the false-positive section; never skips test cases; flags any rule that depends on a non-default-enabled log field | Rule → Logic (plain English) → ATT&CK mapping → Positive/negative test cases → FP analysis → Performance notes → Tuning guidance |

All three share the same low-level habit: cite MITRE ATT&CK technique IDs,
prefer runnable query syntax (KQL/SPL) over prose, and state assumptions
about data coverage explicitly rather than silently assuming complete
telemetry.

## Worked examples

Each persona was smoke-tested with a realistic analyst question before being
trusted; the full command, question, and response are captured for each:

- [`threat-hunter-example.md`](threat-hunter-example.md) — a service account
  (`svc-backup`) authenticating to three file servers it's never touched
  before. Persona produces a T1078.002 hypothesis, KQL/SPL baseline-comparison
  queries, and an explicit "what would disprove this" check rather than
  jumping to "compromised."
- [`ir-responder-example.md`](ir-responder-example.md) — an EDR alert for
  suspected Cobalt Strike beaconing on `WIN-HR-03`. Persona prioritizes
  read-only evidence collection (process tree, connection history, memory
  indicators) over any host action, and labels the beacon itself as
  unconfirmed until process/memory evidence corroborates the EDR heuristic.
- [`detection-engineer-example.md`](detection-engineer-example.md) — a Sigma
  rule for the `msiexec.exe`-installing-from-a-URL pattern (T1218.007). This
  one is grounded in a real companion exercise: the persona read the actual
  ClickFix → Matanbuchus 3.0 → AstarionRAT threat intel and test plan from
  [`purple-team`](../purple-team)
  rather than inventing a generic pattern, and the resulting rule matches the
  exact mixed-case evasion string (`mSiexeC.EXe`) documented in that
  exercise's threat intel.

## Repo layout

```
personas/
├── README.md                     <- this file
├── CLAUDE.md                     <- standing project brief
├── personas/                     <- system prompt files (used via --append-system-prompt-file)
│   ├── threat-hunter.md
│   ├── ir-responder.md
│   └── detection-engineer.md
├── threat-hunter-example.md      <- worked session: service-account lateral-movement hypothesis
├── ir-responder-example.md       <- worked session: Cobalt Strike beacon triage
└── detection-engineer-example.md <- worked session: Sigma rule for the Matanbuchus msiexec pattern
```

## Usage

```
claude --append-system-prompt-file personas/threat-hunter.md
claude --append-system-prompt-file personas/ir-responder.md
claude --append-system-prompt-file personas/detection-engineer.md
```

Global copies also live at `~/.claude/personas/` so they're available outside
this repo; the versioned copies here are the source of truth.

## Skills demonstrated

**Security:**
- Codifying distinct analyst mental models — hypothesis-driven hunting,
  evidence-preservation IR discipline, adversarial skepticism in detection
  engineering — as structured, reusable prompts rather than one-off habits
- Enforcing ATT&CK mapping, falsifiable hypotheses, and fact-vs-inference
  labeling as *default* behaviors that fire on every response, not something
  the analyst has to remember to ask for
- Producing artifacts directly usable in a SOC workflow: runnable KQL/SPL
  hunt queries, an IR timeline/IOC table format, and a fully documented Sigma
  rule with test cases, an honest FP analysis, and tuning guidance
- Grounding the detection-engineer example in real analyst tradecraft: pulling
  the exact Matanbuchus/ClickFix `msiexec` pattern from a companion
  purple-team exercise's threat intel instead of inventing a generic rule

**AI/agentic engineering:**
- Using `--append-system-prompt-file` to compose persona behavior on top of
  Claude Code's baseline without modifying the base install, and validating
  each persona empirically (a smoke-test invocation with a realistic
  question) rather than assuming a prompt "works" once written
- Designing personas with hard behavioral constraints, not just tone — e.g.
  the IR responder is barred from suggesting host-modifying or
  evidence-destroying actions, and the detection engineer is barred from a
  hand-waved "low FP expected" — constraints that matter because these
  prompts are meant to be trusted against real incidents
- Structuring output format as an enforceable contract (hypothesis → evidence
  → pivots → conclusion; TL;DR → timeline → findings → IOCs → gaps → next
  steps; rule → logic → ATT&CK → tests → FP → performance → tuning) so
  responses stay consistent and diffable across sessions
- Laying groundwork for Claude Code's **output styles** system: personas are
  written so they can be lifted directly into `~/.claude/output-styles/` with
  YAML frontmatter (`name`/`description`/`keep-coding-instructions`), turning
  a session-scoped CLI flag into a reusable, first-class Claude Code feature

## Build notes

- **Output-style conversion is in progress, not complete.** `threat-hunter.md`
  is queued for conversion to `~/.claude/output-styles/threat-hunter.md` with
  YAML frontmatter; the other two personas haven't been converted yet.
- **Personas are invoked manually today** via the `--append-system-prompt-file`
  flag, not yet wired into a slash command or `SessionStart` hook that would
  let a user swap personas without remembering the exact CLI invocation.
- **Example sessions are single-turn smoke tests**, not multi-turn
  investigations — they demonstrate the persona follows its format and
  constraints on a realistic first question, not a full worked case study.
