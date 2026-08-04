---
name: purple-loop
description: Run the complete purple team loop from threat intel to tracking
---

# Purple Team Loop Orchestration

Guide through a complete purple team exercise.

## Workflow Steps

### Step 1: Threat Intel
Ask: "What threat report or campaign do you want to simulate? Provide a URL or paste the content."
Action: Run /ingest-ti to process

### Step 2: Test Planning  
Action: Use atomic-mapper agent to find matching Atomic Red Team tests
Output: Test plan with commands and expected telemetry

### Step 3: Execution Checklist
Provide:
- Invoke-AtomicTest commands to run
- Expected log locations
- EVTX export commands for after execution

Ask: "Run the tests in your lab, then let me know when you've exported the logs."

### Step 4: Detection Analysis
Ask: "Where are the EVTX files?"
Action: Use hayabusa to scan the logs
Output: Detection results grouped by severity

### Step 5: SIEM Validation
Action: Run /query for key techniques
Output: Confirm SIEM correlation is working

### Step 6: Gap Analysis
Compare:
- Techniques tested vs detected
- Hayabusa vs SIEM results
- Expected vs actual telemetry
Output: Coverage summary and gaps identified

### Step 7: Documentation
Ask: "Generate the exercise report? (DOCX for team, PPTX for leadership)"
Provide: Summary ready for Claude Desktop document generation

### Step 8: Tracking Reminder
Output: Summary formatted for Vectr entry
Remind: "Update Vectr with these results to track coverage over time."

## Throughout
- Summarize progress at each transition
- Offer to pause and create handoff document
- Maintain context between steps
