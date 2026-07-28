---
date: 2026-07-27
tags: [siem, splunk, investigation, threat-hunt]
techniques: []
query_file: queries\lsass-access.txt
timerange: -15y to now
result_count: 0
status: closed-no-data
---

# Investigation: lsass-access

## Summary of findings

**No results — and no data exists to find.** This hunt looks for Sysmon
**EventID 10 (ProcessAccess)** events where `TargetImage` is `lsass.exe`, the classic
signal for credential dumping from LSASS memory.

Verified against the full dataset (`earliest=0`): the `botsv3` Sysmon source
(`xmlwineventlog:microsoft-windows-sysmon/operational`, 9,212 events) contains
EventIDs **1, 2, 3, 4, 5, 6, 8, 11, 12, 13, 15** — but **no EventID 10 at all**.
The Sysmon config used when this dataset was captured did not log ProcessAccess, so
LSASS-access hunting is not possible on BOTS v3. This is a property of the dataset,
not a detection gap in the environment.

Two setup issues were also identified and corrected while triaging this hunt:
- The query's sourcetype was capitalized (`XmlWinEventLog:...`) but the data is indexed
  lowercase (`xmlwineventlog:...`); Splunk sourcetype matching is case-sensitive.
- Sysmon fields (`EventCode`, `TargetImage`, `SourceImage`, `GrantedAccess`) are **not
  extracted** because the Sysmon add-on (TA) is not installed — events are raw XML.

## Query

Result count: **0**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*lsass.exe"
| stats count values(SourceImage) as source_processes values(GrantedAccess) as granted_access by Computer TargetImage
| sort - count
```

Timerange: `-15y` -> `now` (data is from August 2018; also tested with `earliest=0`).

## Notable events

None. No EventID 10 records exist in `index=botsv3`.

## Analyst notes

<!-- Space for the human analyst. -->
- [ ] Confirmed true positive / false positive: N/A - no data
- [ ] Affected hosts & accounts: N/A
- [ ] Containment actions: N/A
- [ ] Escalation needed: No
- Notes: Retarget credential-access hunting to techniques that DO have data in BOTS v3
  (e.g. process-creation EventID 1: PowerShell, LOLBins, scheduled tasks). Field
  extraction must be resolved first - either install the Sysmon TA or use inline
  `rex`/`spath` extraction in the query.
