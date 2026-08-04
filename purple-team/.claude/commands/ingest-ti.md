---
name: ingest-ti
description: Process a threat intelligence report and extract actionable TTPs
---

# Threat Intelligence Ingestion

Process a threat report URL or pasted content to extract TTPs for simulation.

## Process

1. **Fetch content** (if URL provided)
   - Use defuddle-cli to extract clean content: `defuddle <url> `
   - If defuddle unavailable, use web_fetch or ask user to paste content

2. **Extract TTPs** (use extended thinking)
   - Identify attack techniques described in the report
   - Map each to MITRE ATT&CK technique IDs
   - Note the kill chain phase and dependencies
   - Assess confidence level for each mapping

3. **Generate simulation plan**
   - Group techniques by kill chain phase
   - Identify which can be safely simulated in a lab
   - Flag any that require special infrastructure

## Output Format

# Threat Intel Analysis: [Campaign/Report Name]

## Extracted TTPs

| Technique | ID | Confidence | Priority |
|-----------|-----|------------|----------|
| [Name] | T#### | High/Med/Low | Simulate/Skip |

## Simulation Plan

### Phase 1: [Kill Chain Phase]
- [Technique]: [How to simulate]

## Infrastructure Requirements
- [Any special requirements]

## Detection Opportunities
- [What to look for]
