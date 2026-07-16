# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A detection-engineering knowledge base: Sigma detection rules (`rules/**/*.yml`) and YARA-X malware detection rules (`rules/yara/*.yar`), governed by house standards defined in `.claude/skills/detection-engineering/SKILL.md`.

## Commands

Validate a Sigma rule against the house standards (ATT&CK tag, severity+justification, false positives, test case, naming):

```
python .claude/skills/detection-engineering/scripts/validate-rule.py <path-to-rule.yml>
```

Exits `0` (all checks pass), `1` (at least one check fails — see the `issues` array in the printed JSON report), or `2` (usage/parse error).

Lint/analyze a YARA rule (style, metadata, naming, and atom-quality/performance checks) via the `yara-authoring` plugin's scripts:

```
python "<yara-authoring plugin dir>/scripts/yara_lint.py" <path-to-rule.yar>
python "<yara-authoring plugin dir>/scripts/atom_analyzer.py" <path-to-rule.yar>
```

Both require the `yara-x` Python bindings (`pip install yara-x`); the `yr` CLI itself requires a Rust toolchain (`cargo install yara-x`) which is not installed in this environment — use the pip-installed Python bindings instead when `yr` is unavailable.

There is no build step, package manifest, or CI config in this repo — it is rule/documentation content plus small standalone Python validation scripts, not an application.

## Architecture

**Two rule formats, two locations:**
- Sigma rules live under `rules/<category>/` (e.g. `rules/credential_access/`) or directly under `rules/` for rules without a clear category yet.
- YARA-X rules live under `rules/yara/`.

**Every rule ships with a colocated test file**, not inline tests: `<rule_name>.yml` pairs with `<rule_name>.test.yml` in the same directory. The test file has a `tests:` (or `test_cases:`) list of `{name, description, should_match, log}` entries — at least one `should_match: true` (true positive) is required; false-positive/negative cases are expected but not required by the validator.

**Standards are enforced by a skill, not by CI.** `.claude/skills/detection-engineering/SKILL.md` defines five required elements for every Sigma rule (ATT&CK `attack.tXXXX` tag in `tags`, `level` in {low,medium,high,critical} with a justification in `description` or a `# Severity:` comment, concrete `falsepositives` entries, at least one test case, lowercase_with_underscores naming). `.claude/skills/detection-engineering/scripts/validate-rule.py` mechanically checks all five and is the fast first-pass check before manual review — it validates metadata/documentation completeness only, not detection-logic correctness. `.claude/skills/detection-engineering/references/` holds supporting material: `example-rules/` (a fully-compliant template rule + test file), `severity-guide.md`, and `false-positive-patterns.md`.

**YARA rules follow the `yara-authoring` plugin's conventions** (installed via the `trailofbits` marketplace, cached under the Claude Code plugins directory, not part of this repo's own source): filename/rule-name pattern `{CATEGORY}_{PLATFORM}_{FAMILY}_{VARIANT}_{DATE}` (e.g. `MAL_Win_CobaltStrike_Beacon_Jul26.yar`), required metadata (`description` starting with "Detects", `author`, `reference`, `date`), and an atom-quality bar — strings under 4 bytes or built from repeated/low-entropy byte runs get flagged by `atom_analyzer.py` as causing slow scans even when semantically correct (e.g. XOR-key-recovery patterns are inherently repeated-byte and will always trip this warning; that's an accepted, documented tradeoff rather than a bug to silence).

**When writing or reviewing a rule of either format, load the corresponding skill first** (`detection-engineering` for Sigma, `yara-authoring:yara-rule-authoring` for YARA-X) rather than freehanding metadata/structure — both skills encode non-obvious conventions (e.g. severity justification placement, atom-quality heuristics) that aren't inferable from reading one example file.
