# STATE.MD

Snapshot of repo state as of 2026-07-16. This file tracks *current* status; update it as rules/tooling change rather than appending history (see HANDOFF.md for chronological session notes).

## Rule inventory

**Sigma (`rules/`):** 3 rules, all passing `validate-rule.py` with no outstanding issues.

- `credential_access/lsass_memory_dump_via_minidump.yml` — high — T1003.001
- `credential_access/sam_registry_hive_dump_via_reg_save.yml` — high — T1003.002
- `azure_app_ropc_authentication.yml` — medium — T1078 (test coverage added 2026-07-16; previously missing)

**YARA-X (`rules/yara/`):** 1 rule.

- `MAL_Win_CobaltStrike_Beacon_Jul26.yar` — two sub-rules (`XORConfig`, `DefaultArtifacts`). Passes `yara_lint.py` clean. `atom_analyzer.py` flags `XORConfig`'s two repeated-byte strings as slow-scanning atoms (score 10/100) — this is an **accepted, documented tradeoff** (see rule's header comment), not an open defect: the detection technique (matching XOR-decoded zero-padding runs) inherently produces low-entropy atoms. Not yet tested against real Beacon samples or a goodware corpus — no samples were available in this session.

## Tooling status

- `.claude/skills/detection-engineering/scripts/validate-rule.py` — working, exercised against all 3 Sigma rules.
- `yara-authoring` plugin (`trailofbits` marketplace) — installed and its skill loaded successfully.
  - `yr` CLI (Rust binary) — **not installed**; `cargo` is not on PATH in this environment, so `cargo install yara-x` fails. `yr check`/`yr fmt` have not been run against the YARA rule.
  - `yara-x` Python bindings — installed via `pip install yara-x` (v1.19.0) this session, which unblocked `yara_lint.py` and `atom_analyzer.py`.

## Known gaps

- No goodware/clean-sample validation has been performed on any rule in this repo (required by both skills before "production" deployment status — all rules are currently `status: experimental`/`test`, appropriately).
- The Cobalt Strike YARA rule has not been tested against real Beacon samples.
- `yr check` / `yr fmt` (the Rust CLI) have never been run in this environment — only the Python-bindings-based lint/atom scripts have.
- No CI/automation runs these validators automatically; they are manual/on-request only.
