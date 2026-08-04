---
name: query
description: Run a SIEM query, map results to ATT&CK, and generate investigation notes
---

# SIEM Query and Documentation

Run a query against the SIEM and generate Obsidian-compatible investigation notes.

## Process

1. **Build the query**
   - Translate the user's request into SIEM query syntax
   - Default to Splunk SPL (adjust for your SIEM)

2. **Execute the query**
   - If SIEM MCP is available, use it
   - Otherwise, provide the query for manual execution
   - Ask user to paste results if needed

3. **Analyze results**
   - Identify key findings
   - Map to ATT&CK techniques where applicable
   - Note anomalies or items needing follow-up

4. **Generate Obsidian notes**
   - Use `[[backlinks]]` for techniques, IOCs, investigations
   - Format for graph view integration

## Output Format

# Query Results: [Description]

## Query

    [The query in SPL/KQL/etc]

## Results Summary
[Key findings]

## ATT&CK Mapping
- Technique: [[T####.### - Name]]
- Tactic: [[Tactic Name]]

## Investigation Notes
Created: [[Investigation-YYYY-MM-DD-Topic]]
IOCs: [[IOC-description]]

## Follow-up Actions
- [ ] [Next steps]
