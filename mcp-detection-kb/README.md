# mcp-detection-kb

A detection-engineering knowledge base of Sigma detection rules and YARA-X malware detection rules, built to a consistent, mechanically-checked set of quality standards rather than ad hoc "looks good to me" review.

> Built as part of [module 5, "Skills - Codifying Methodology"](https://www.justhacking.com/course/ai-cyber-defense-ops/), from Just Hacking Training's *AI Cyber Defense Ops* course.

## Why this exists

Detection rules rot in ways that are easy to miss in review: an ATT&CK tag gets left off, `falsepositives` gets left as "Unknown", a severity gets picked on gut feel with no justification anyone can audit later, a rule ships with no evidence it ever matched anything. None of that shows up as a syntax error - the rule still loads and "works." This repo codifies what "done" means for a rule as an explicit skill (`.claude/skills/detection-engineering/`) with a companion script that checks it mechanically, so the standard doesn't depend on the reviewer remembering to ask the right questions every time.

## What it does

**Sigma rules** (`rules/`), each with a colocated `<rule_name>.test.yml` of sample log events:

| Rule | Technique | Severity |
|---|---|---|
| [`credential_access/lsass_memory_dump_via_minidump.yml`](rules/credential_access/lsass_memory_dump_via_minidump.yml) | T1003.001 - LSASS Memory | high |
| [`credential_access/sam_registry_hive_dump_via_reg_save.yml`](rules/credential_access/sam_registry_hive_dump_via_reg_save.yml) | T1003.002 - SAM | high |
| [`azure_app_ropc_authentication.yml`](rules/azure_app_ropc_authentication.yml) | T1078 - Valid Accounts | medium |

**YARA-X rules** (`rules/yara/`):

| Rule | Target |
|---|---|
| [`MAL_Win_CobaltStrike_Beacon_Jul26.yar`](rules/yara/MAL_Win_CobaltStrike_Beacon_Jul26.yar) | Cobalt Strike Beacon - XOR-obfuscated config block + default artifact-template leftovers, split into two sub-rules by confidence level |

**The standard itself** lives in `.claude/skills/detection-engineering/SKILL.md`: every Sigma rule must carry an explicit ATT&CK `attack.tXXXX` tag, a `level` with a stated justification (not a bare severity), concrete `falsepositives` entries (not "Unknown"), at least one test case, and lowercase_with_underscores naming. `.claude/skills/detection-engineering/references/` backs this with a severity-selection guide, a catalog of common false-positive patterns to check against, and a fully-worked example rule. YARA-X rules follow the separately-installed `yara-authoring` plugin skill's conventions (`{CATEGORY}_{PLATFORM}_{FAMILY}_{VARIANT}_{DATE}` naming, required metadata, an atom-quality bar).

## Example usage

Validate a Sigma rule against the standard - prints a JSON report, exit `0`/`1`/`2` for pass/fail/usage-error:

```bash
python .claude/skills/detection-engineering/scripts/validate-rule.py rules/credential_access/lsass_memory_dump_via_minidump.yml
```

Lint and atom-check a YARA-X rule (needs `pip install yara-x` for the Python bindings; the `yr` Rust CLI needs `cargo`, which was not available in the build environment):

```bash
python "<yara-authoring plugin dir>/scripts/yara_lint.py" rules/yara/MAL_Win_CobaltStrike_Beacon_Jul26.yar
python "<yara-authoring plugin dir>/scripts/atom_analyzer.py" rules/yara/MAL_Win_CobaltStrike_Beacon_Jul26.yar
```

## Skills demonstrated

- Sigma rule authoring and ATT&CK technique mapping, including deliberately choosing a *different* sub-technique (T1003.002 over T1003.001) rather than duplicating existing coverage
- YARA-X rule authoring: atom-quality tradeoffs, and recognizing when a linter warning is an inherent property of the detection technique (XOR-key recovery via repeated-byte runs) rather than a defect to silence
- Turning a written standard into a mechanically-enforced check (`validate-rule.py`) instead of leaving compliance to reviewer memory
- Working around missing tooling in the actual build environment (no `cargo`/`yr` CLI) by installing the Python bindings instead of blocking on it
- Auditing an existing rule against the standard, finding the one real gap (missing test evidence), and closing it rather than rewriting what already worked

## Known limitations

- No goodware/clean-sample corpus testing has been run against any rule here - all rules are appropriately marked `experimental`/`test`, not production-ready.
- The Cobalt Strike YARA rule has not been tested against real Beacon samples, only written from documented public indicators.
- The `yr` Rust CLI has never run in this environment - only the Python-bindings-based lint/atom scripts have. `yr check`/`yr fmt` are still outstanding.
- No CI wires the validators in automatically; they're run on request.

See [HANDOFF.md](HANDOFF.md) for the full build narrative and design rationale, and [STATE.MD](STATE.MD) for the current checkpoint.
