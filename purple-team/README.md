# purple-team — an end-to-end purple team loop, from threat intel to detection validation

> **AI Cyber Defense Ops — Module 10: End-to-End Purple Team Workflow**

A Claude Code workspace that runs a complete purple-team exercise as one continuous,
artifact-driven workflow: **ingest threat intel → map to Atomic Red Team tests → simulate the
attacker behavior → scan the resulting telemetry with a detection engine → validate in the SIEM →
gap-analyze → report**. It stitches together the individual capabilities built earlier in the
course (MCP server, slash commands, subagents) into a single guided loop, and adds the missing
piece needed to actually close it: turning simulated activity into **binary event logs a detection
engine will parse**.

The exercise shipped here validates two priority techniques from a real February 2026 intrusion
chain (a ClickFix social-engineering lure delivering a commodity loader and a custom RAT, followed
by hands-on-keyboard domain reconnaissance and rogue-admin creation): **Domain Group Discovery
(T1069.002)** and **Create Local Admin (T1136.001 / T1098)**, with **Remote System Discovery
(T1018)** bundled in.

## What it does

Three slash commands and one subagent, orchestrated by a top-level loop:

| Command / agent | Role in the loop |
|---|---|
| `/ingest-ti <url>` | Fetches and parses a threat report, extracts TTPs, maps each to MITRE ATT&CK, and produces a lab-safe simulation plan. |
| `atomic-mapper` (subagent) | Maps each "simulate" technique to concrete Atomic Red Team tests — command line, expected telemetry / Event IDs, cleanup, and DC-vs-workstation placement. |
| `/query <search>` | Translates the hunt into SIEM query syntax (Splunk SPL by default), maps results to ATT&CK, and writes Obsidian-linked investigation notes. |
| `/purple-loop` | Orchestrates all eight steps end to end, carrying context between stages and summarizing at each transition. |

Detection analysis is driven by the **Hayabusa** MCP server (`scan_evtx`) against Windows event
logs; findings are grouped by severity and diffed against the test plan for coverage gaps.

### The loop, concretely

1. **Threat intel** → TTP table + simulation plan (`threat-intel.md`)
2. **Test planning** → Atomic Red Team mapping (`test-plan.md`, `atomics/*.yaml`)
3. **Execution** → attacker commands + expected telemetry (lab or, here, simulated)
4. **Detection** → Hayabusa scan → severity-ranked hits (`findings.md`)
5. **SIEM validation** → portable SPL for the same behavior
6. **Gap analysis** → tested-vs-detected, engine-vs-SIEM, expected-vs-actual
7. **Documentation** → a sanitized, shareable report (`report.pdf`)
8. **Tracking** → a summary formatted for coverage tracking over time

## Engineering highlight — making simulated activity scannable

Hayabusa parses **binary `.evtx` only**; a rendered-XML event export is silently ignored and comes
back as *zero findings* — indistinguishable, at a glance, from a genuine detection gap. To close the
loop without a live lab detonation, this project includes a small **synthetic-EVTX writer** that
turns human-readable event XML into a valid single-chunk EVTX the engine will actually parse.

The instructive part was the debugging: the first output parsed as *zero events*. The root cause was
that BinXML element-name offsets are **absolute from the chunk start**, not relative to each record —
a subtle format detail that a lenient reader tolerates but the detection engine's stricter parser
rejects wholesale. The fix (a two-pass build that resolves absolute offsets) is documented in
[`HANDOFF.md`](HANDOFF.md), along with the validation method that told parse-failure apart from
no-detection: run the engine directly and read its *event-count* line, not just its findings count.

## Results (this exercise)

- **21 rule hits across 10 events** — 6 high, 6 medium, 9 low. Both focus techniques detected at
  **high** severity.
- The `net.exe → net1.exe` child pair was fully caught — naive rules keyed only on `net.exe` would
  miss half the activity.
- **One real gap:** adding an account to a **non-existent localized group name** (the operator's
  first attempt used a non-English group) produces **no group-membership audit event** — it is only
  visible on the process command line. A correlation rule joining the audit event with the process
  event is the recommended fix.

## Repo layout

```
purple-team/
├── README.md                 <- this file
├── CLAUDE.md                 <- standing project brief
├── HANDOFF.md / STATE.md     <- build narrative + point-in-time state
├── .claude/
│   ├── commands/             <- /ingest-ti, /query, /purple-loop
│   └── agents/               <- atomic-mapper subagent
└── exercises/
    └── 2026-08-04/
        ├── threat-intel.md   <- ingested report: TTPs, sim plan
        ├── test-plan.md      <- Atomic Red Team mapping
        ├── atomics/          <- sample ART test definitions
        ├── evtx/             <- sample event XML + synthetic .evtx
        ├── findings.md       <- Hayabusa detection results by severity
        └── report.pdf        <- sanitized exercise report (shareable)
```

## Setup

1. **Claude Code** with the **Hayabusa** MCP server configured (see the `mcp-hayabusa` tool in the
   companion repo). `scan_evtx` requires the Hayabusa binary on the host.
2. **Python 3** for the report and EVTX-generation helpers (`reportlab`, `pypdf`).
3. Open the folder in Claude Code and run `/purple-loop`, or invoke the individual commands.

## Skills demonstrated

**Security:**
- Turning a narrative threat report into an actionable, lab-safe simulation plan mapped to MITRE
  ATT&CK, with confidence and priority per technique
- Detection validation as a measurable loop: techniques tested vs. detected, engine vs. SIEM,
  expected vs. actual telemetry — and surfacing the coverage gap, not just the wins
- Recognizing a real detection blind spot (localized/failed group-name adds that generate no audit
  event) and specifying the correlation logic that closes it
- Faithful adversary emulation: reproducing the observed process lineage, staging location, and the
  operator's own command sequence so the simulation exercises the same telemetry the intrusion did

**AI / agentic engineering:**
- Composing an end-to-end workflow from previously built pieces (MCP server, slash commands, a
  scoped subagent) into one guided, artifact-driven loop that is rerunnable and hand-off-friendly
- Writing a small binary-format encoder (synthetic EVTX) to bridge a real tool boundary, and
  debugging it against ground truth — distinguishing a *parse failure* from a *no-detection* result
  rather than trusting a zero-count at face value
- Treating the detection engine as an untrusted boundary: validating its input format explicitly
  instead of assuming a rendered export would be accepted
- Sanitization discipline in generated deliverables: the shareable report is programmatically
  stripped of credentials, passphrases, keys, hashes, and account identifiers, and the redaction is
  verified by re-reading the output

## Build notes (honest state)

- **Execution stage is simulated, not detonated.** The telemetry here is synthetic EVTX generated
  from sample event XML — the detection logic exercised is production Sigma/Hayabusa, but the events
  are lab-authored. A live-lab run would additionally validate EDR-native fields and real file
  hashes. This is called out in `STATE.md` / `HANDOFF.md`.
- **SIEM validation is authored, not yet executed.** Portable SPL exists for each technique but has
  not been run against a live SIEM, so SIEM coverage is *projected*, not *confirmed*.
- **The EVTX generator lives outside the tracked tree** (in a session scratchpad) and should be
  moved into a `scripts/` folder to be version-controlled with the exercise — noted, not yet done.
