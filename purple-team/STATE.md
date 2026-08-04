# STATE — Purple Team Workflow

_Last updated: 2026-08-04_

## Current exercise: `exercises/2026-08-04/`

**Campaign:** ClickFix → Matanbuchus 3.0 → AstarionRAT (Huntress, Feb 2026)
**Focus techniques:** T1069.002 Domain Groups · T1136.001 / T1098 Create Local Admin
**Lab:** ConDef (DC, Win11v + Sysmon, Splunk)

## Purple-loop progress

| Step | Status | Notes |
|------|--------|-------|
| 1 · Threat Intel | ✅ done | `threat-intel.md` |
| 2 · Test Planning | ✅ done | `test-plan.md` (atomic-mapper, 20 techniques) |
| 3 · Execution | ⚠️ simulated | synthetic EVTX, NOT a live lab detonation |
| 4 · Detection | ✅ done | `findings.md` — 21 hits (6 high / 6 med / 9 low) |
| 5 · SIEM Validation | ◻️ queries built, not run | SPL authored; not executed against Splunk |
| 6 · Gap Analysis | ✅ done | in `findings.md` + `report.pdf` |
| 7 · Documentation | ✅ done | `report.pdf` (sanitized, TLP:AMBER) |
| 8 · Vectr Tracking | ◻️ pending | entry drafted, not yet written to file |

## Open items
- [ ] Run the Step 5 Splunk SPL → mark SIEM coverage **confirmed** (update `findings.md` + `report.pdf`)
- [ ] Close the `Administradores` gap: correlation rule joining Security 4732 + Sysmon `net localgroup */add`
- [ ] (Optional) Move `mk_evtx.py` generator out of scratchpad into `scripts/` for version control
- [ ] (Optional) Live-lab detonation (Option A) to validate EDR-native fields / real hashes
- [ ] Write Vectr import entry (`exercises/2026-08-04/vectr-import.md`)

## Known constraints
- **Hayabusa MCP scans binary `.evtx` only** — rendered XML is ignored (returns 0 findings silently).
- No Splunk MCP connected — SIEM queries must be run manually.
- EVTX in this exercise is **synthetic** (generated from sample XML); detection logic is real, provenance is not.
