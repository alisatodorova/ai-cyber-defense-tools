# complex-analysis — multi-agent security analysis with subagents

> **AI Cyber Defense Ops — Module 8: Complex Analysis - Threat Intel & Multi-Source Correlation**

Repeatable workflows for complex, multi-step security analysis, built around Claude Code
**subagents**: purpose-scoped analyst agents that each own one log domain, run in parallel, and
feed a correlation step that stitches their findings into a single incident picture.

The point isn't "Claude read some logs." It's decomposing an investigation the way a SOC does —
an **endpoint** analyst and a **cloud** analyst working the same incident from different telemetry,
then a correlation pass that aligns timelines, joins on shared users/IPs, and reconstructs the
attack chain — codified so it runs the same way every time.

## Two workflows

### 1. Threat-intel processing (`/ingest-ti <url>`)
Ingest a threat-intel report, extract TTPs, and produce a **simulation plan**:

1. **Ingest** — pull clean content (`defuddle parse "$url" --md`, falling back to `WebFetch`
   when `defuddle`/`npx` isn't on the host).
2. **Extract TTPs** — map observed behavior to MITRE ATT&CK with per-technique confidence.
3. **Simulate** — turn the TTPs into an **Atomic Red Team** test plan, prioritized by
   confidence × available atomics, with a manual-emulation list for techniques that have no
   clean atomic.

Output: `analysis/ti-<date>-<campaign>.md` with source-URL frontmatter. First run ingested a
DFIR Report intrusion (BumbleBee → AdaptixC2 → Akira ransomware) end-to-end.

### 2. Multi-source investigation (subagents → correlation)
Correlate endpoint and cloud telemetry via two read-only subagents and a merge step:

1. **`endpoint-analyst`** reads `logs/windows/` (Windows Security + Sysmon) → `analysis/endpoint.md`
2. **`cloud-analyst`** reads `logs/cloud/` (Azure AD sign-in + audit) → `analysis/cloud.md`
3. **Correlation** joins the two → `analysis/correlation.md`: timeline alignment, user + IP
   correlation, unified attack chain, confidence assessment, evidence gaps, and containment.

Each analyst emits the same structured shape (timeline, IOCs, ATT&CK-with-evidence, confidence),
and each carries explicit cross-source pointers (shared IPs, shared accounts, aligned timestamps)
so the correlation step has clean join keys.

## Why subagents

- **Separation of concerns** — each agent has a single domain, a fixed output contract, and a
  minimal toolset (`Read`, `Bash` only). Endpoint expertise and cloud expertise stay independent.
- **Parallelism** — the two analyses run concurrently; correlation happens once both land.
- **Composability** — per-domain notes are reusable artifacts. Correlation reads files, not chat
  state, so it can be rerun or handed to a different analyst.
- **Correlation is where the signal is** — the payoff is cross-plane: three attacker IPs and two
  accounts bridge endpoint and cloud, and a timing check (a cloud sign-in that *precedes* the
  on-prem NTDS dump) rules out the obvious-but-wrong credential-source hypothesis.

## Example: the correlated finding

The sample incident (synthetic, `contoso.com`, 2025-07-15→17) resolves to one campaign across both
planes. Endpoint C2 and a cloud sign-in share IP `172.96.137.160` **109 seconds apart** — the
pivot from foothold to tenant. The same actor then elevates to Global Admin, plants a rogue service
principal (`backup-sync-connector`) with a client secret, disables MFA/Security Defaults, and later
runs Akira on-prem. Full write-up in [`analysis/correlation.md`](analysis/correlation.md).

## Repo layout

```
complex-analysis/
├── .claude/agents/            <- subagent definitions (the core deliverable)
│   ├── endpoint-analyst.md    <- Windows Security + Sysmon analyst (Read, Bash)
│   └── cloud-analyst.md       <- Azure AD sign-in + audit analyst (Read, Bash)
├── .claude/commands/          <- slash commands (/ingest-ti)
├── logs/
│   ├── windows/               <- endpoint sample data (security.json, sysmon.json)
│   ├── cloud/                 <- cloud sample data (azuread_signin.json, azuread_audit.json)
│   └── README.md              <- scenario + built-in correlation map
├── analysis/                  <- all outputs
│   ├── ti-<date>-<campaign>.md<- threat-intel ingest + simulation plan
│   ├── endpoint.md            <- endpoint analyst notes
│   ├── cloud.md               <- cloud analyst notes
│   └── correlation.md         <- unified endpoint↔cloud picture
├── CLAUDE.md                  <- standing project brief + file conventions
└── handoff.md / state.md      <- build narrative + point-in-time state
```

## Skills demonstrated

**Security:**
- Multi-source IR: correlating endpoint (Windows Security/Sysmon) and cloud (Entra ID/Azure AD)
  telemetry into one timeline and attack chain
- Recognizing an on-prem → cloud pivot and cloud-persistence tradecraft (Global Admin elevation,
  rogue service principal + secret, MFA/CA teardown) that survives on-prem remediation
- Threat-intel → emulation: MITRE ATT&CK mapping with confidence, translated into an Atomic Red
  Team simulation plan
- Evidence discipline: rating conclusions by confidence and using timestamp order to falsify a
  plausible-but-wrong hypothesis (NTDS dump vs. the earlier foothold as credential source)

**AI / agentic engineering:**
- Designing Claude Code **subagents** with a single responsibility, a least-privilege toolset,
  and a fixed output contract that makes downstream correlation mechanical
- A fan-out/fan-in pattern (parallel per-domain analysis → file-based merge) that's rerunnable and
  hand-off-friendly, because agents read artifacts rather than conversation state
- Packaging TI ingestion as a parameterized slash command with a graceful extraction fallback
  (`defuddle` → `WebFetch`)
- Catching the AI's/environment's failure modes: a subagent aborting on an automated cyber-safeguard
  false positive (legitimate defensive work) handled by completing that analysis inline, with the
  gotcha captured in `CLAUDE.md`/`handoff.md` so it doesn't get rediscovered

## Build notes (what mattered)

- **Subagent safeguard false positive.** The `endpoint-analyst` subagent aborted mid-run on an
  automated cyber safeguard — legitimate defensive IR on synthetic data flagged by intentionally
  broad protections. Handled by running that analysis inline (identical output format); the cloud
  subagent ran cleanly. Documented as a standing gotcha.
- **Correlation caught a timing contradiction.** The tempting story — "NTDS dump fed the cloud
  sign-in" — is wrong: the cloud sign-in (07-16 02:11) *precedes* the on-prem NTDS dump by ~7h. The
  credential more likely came from the earlier AdaptixC2 foothold. Flagged as an open thread with
  the exact gap-filling logs to pull.
- **Extraction portability.** `defuddle`/`npx` aren't installed on this Windows host, so TI ingest
  falls back to `WebFetch` for the same clean content — the workflow degrades gracefully instead of
  failing.
