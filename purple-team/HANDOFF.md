# HANDOFF — Purple Team Exercise 2026-08-04

Context transfer for the next operator/session. Pairs with `STATE.md` (quick status).

## 1. What this exercise is

A purple-team validation of two priority techniques from the Huntress **ClickFix →
Matanbuchus 3.0 → AstarionRAT** intrusion (Feb 2026), run in the **ConDef** lab
(DC, Win11v + Sysmon, Splunk). Goal: confirm detection coverage for the operator's
hands-on-keyboard Discovery and Persistence activity.

- **T1069.002** Domain Groups — `net group "Domain Admins" /domain` (net.exe → net1.exe)
- **T1136.001 / T1098** Create Local Admin — rogue `DefaultService` account, add to
  `Administradores` (Spanish, fails on EN host) then `Administrators`
- **T1018** Remote System Discovery — `nltest /dclist:` (bundled)

Simulated attacker context: AstarionRAT dispatcher → `cmd.exe` → `net.exe`, staging from
a ProgramData path that imitates a legitimate Windows Update directory, compromised
service account `svc-backup`.

## 2. Deliverables (all under `exercises/2026-08-04/`)

| File | What it is |
|------|-----------|
| `threat-intel.md` | Ingested report: TTP table, sim plan, IOCs, YARA links |
| `test-plan.md` | atomic-mapper output: 20 techniques → Atomic Red Team tests + telemetry |
| `atomics/T1069.002.yaml`, `atomics/T1136.001.yaml` | Sample ART tests, intrusion-faithful inputs |
| `evtx/sim-*.xml` | Rendered event XML (human-readable source) |
| `evtx/security.evtx`, `evtx/sysmon.evtx` | **Synthetic binary EVTX** (hayabusa-scannable) |
| `findings.md` | Hayabusa detection results — 21 hits by severity + gap notes |
| `report.pdf` | Sanitized exec report (TLP:AMBER); creds/keys/hashes/SIDs redacted |

## 3. How the synthetic EVTX was produced (important)

Hayabusa's MCP `scan_evtx` parses **binary `.evtx` only** — the rendered XML returns 0
findings silently. No EVTX writer existed on the box, so one was written:

- Generator: `…/scratchpad/mk_evtx.py` (⚠️ in session scratchpad — **move to `scripts/` to keep it**).
- It parses `evtx/sim-*.xml` and emits a single-chunk EVTX with inline (non-template) BinXML.
- **Critical detail:** BinXML name offsets are **absolute from chunk start**, not record-local.
  Getting this wrong yields a file that python-evtx partially reads but hayabusa reports as
  `Total events: 0 / 0`. The two-pass build in `mk_evtx.py` handles this.
- Validation path: run `hayabusa … csv-timeline` directly (binary at
  `E:/ClaudeWork/mcp-hayabusa/hayabusa/hayabusa-3.10.0-win-x64.exe`) and check the
  `Total events` line — that distinguishes a parse failure from a genuine no-detection.

To regenerate:
```bash
python scratchpad/mk_evtx.py exercises/2026-08-04/evtx/sim-security.xml exercises/2026-08-04/evtx/security.evtx
python scratchpad/mk_evtx.py exercises/2026-08-04/evtx/sim-sysmon-operational.xml exercises/2026-08-04/evtx/sysmon.evtx
```

## 4. Results summary

21 hits / 10 events — 6 high, 6 medium, 9 low. Both focus techniques detected at **high**
severity (Sysmon proc-exec; Security 4732 admin-group add). The net.exe→net1.exe pair was
fully caught.

## 5. The one real gap

Adding an account to the **non-existent localized group `Administradores`** produces **no
4732** audit event — it is only visible on the process command line. Any rogue-admin
correlation that keys solely on 4732 (or on the well-known SID `S-1-5-32-544`) will miss
the operator's Spanish-first attempt. **Recommended fix:** correlation search joining
Security 4732 **with** Sysmon `net localgroup */add`.

## 6. Next actions (in priority order)

1. **Run the Step 5 Splunk SPL** (queries in the session's `/query` output — need to be
   saved to `exercises/2026-08-04/siem-query.md`). Verify `index=`/`sourcetype=` match
   ConDef. Then update `findings.md` + `report.pdf`: projected → **confirmed**.
2. **Build the `Administradores` correlation rule** and re-test.
3. **Write the Vectr entry** to `exercises/2026-08-04/vectr-import.md` (draft exists in
   session history — 5 test cases).
4. **Preserve the generator:** move `mk_evtx.py` to `scripts/`.
5. Optional: **live-lab detonation** (test-plan Option A) for EDR-native telemetry.

## 7. Sanitization note

`report.pdf` is the shareable artifact — redacted of the rogue-account password, the
`.7z` archive passphrase, file hashes, and domain SIDs (verified absent). Those values
remain in the working files (`threat-intel.md`, `atomics/*.yaml`, `evtx/sim-*.xml`);
sanitize again before sharing anything other than the PDF.

## 8. Environment gotchas

- Hayabusa MCP = binary EVTX only; rendered XML silently yields nothing.
- No Splunk MCP — SIEM queries are manual.
- `python-evtx` (reader) is stricter than hayabusa's Rust parser on non-template BinXML;
  its parse errors are NOT proof the EVTX is bad — confirm with hayabusa itself.
