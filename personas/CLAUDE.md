# Security Personas — System Prompts

Composable Claude Code system prompts (personas) for security workflows: threat
hunting, incident response, and detection engineering. Each persona is a plain
markdown file layered on top of Claude Code's default behavior via
`--append-system-prompt-file` — no code, no MCP server, just a disciplined
system prompt that constrains tone, output structure, and what the model is
and isn't allowed to suggest.

## Personas

- `personas/threat-hunter.md` — hypothesis-driven investigation mindset. Always
  maps to MITRE ATT&CK, prefers KQL/SPL, states assumptions, and asks what
  would disprove the hypothesis before treating it as confirmed. Output:
  hypothesis → evidence → pivots → conclusion/next hypothesis.
- `personas/ir-responder.md` — active-incident discipline. Treats the host in
  scope as possible evidence: labels every claim observed vs. inferred, never
  suggests host-modifying or evidence-destroying actions unless the user says
  "containment phase". Output: TL;DR → timeline → findings → IOCs → gaps →
  next steps.
- `personas/detection-engineer.md` — skeptical rule author. Sigma by default,
  ATT&CK-tagged, and never allowed to hand-wave a false-positive analysis or
  skip test cases. Output: rule → logic → ATT&CK → test cases → FP analysis →
  performance → tuning.

## Usage

```
claude --append-system-prompt-file personas/<name>.md
```

Global copies also live at `~/.claude/personas/` for ad hoc use outside this
repo; the versioned copies here are the source of truth.

## Example sessions

One worked example per persona (`*-example.md` at the repo root), each
capturing the exact command, a realistic analyst question, and the full
response — used to sanity-check the persona's tone, structure, and
constraints before relying on it in a real investigation.

## Planned

- Convert personas to Claude Code **output styles** (`~/.claude/output-styles/`)
  with YAML frontmatter (`name`, `description`, `keep-coding-instructions: false`)
  so they can be selected via `/output-style` instead of a CLI flag.
