---
name: detection-engineering
description: |
  Detection rule development standards. Activate when:
  - Writing, creating, or modifying Sigma/YARA rules
  - Reviewing detection rules for quality or completeness
  - Discussing detection coverage, gaps, or improvements
  - Working with YAML files containing detection logic
  - Asked to validate, check, or audit detection rules
  - Converting detections between formats (Sigma to KQL, SPL, etc.)
---

# Detection Engineering Standards

Apply these standards to every Sigma/detection rule you write or review. When
reviewing an existing rule, check it against each requirement below and call
out any violations before approving it.

## 1. ATT&CK technique mapping (required)

Every rule must map to at least one MITRE ATT&CK technique in the `tags`
field, formatted as `attack.tXXXX` (lowercase, no hyphen before the number).
Sub-techniques use the dotted form, e.g. `attack.t1059.001`.

```yaml
tags:
  - attack.t1059.001
```

A rule with no `attack.tXXXX` tag is incomplete — do not treat "the query
implies a technique" as sufficient; the tag must be explicit.

## 2. Severity with justification (required)

`level` must be exactly one of: `low`, `medium`, `high`, `critical`.

The rule must also carry a one- or two-sentence justification for that
severity choice. Put it in the `description` field (or a `# Severity:`
comment immediately above `level` if the rule format doesn't have a
description). The justification should reference impact and confidence, e.g.:

```yaml
level: high
description: >
  Detects LSASS memory access consistent with credential dumping.
  Severity is high due to direct impact on credential material and
  low benign-usage rate for this access pattern.
```

Reject severities outside the four allowed values (no `informational`,
no `medium-high`, etc.) and reject a bare `level:` with no justification
anywhere in the rule.

## 3. False positive conditions (required)

Every rule must document known false-positive conditions in the `falsepositives`
field. "Unknown" alone is not acceptable — list the specific legitimate
activity that can trigger the rule (admin tooling, backup agents, specific
software names, etc.):

```yaml
falsepositives:
  - Legitimate use of PsExec by IT administrators
  - Backup software invoking remote service creation
```

If a rule genuinely has no known false-positive sources, that must be stated
explicitly with reasoning (e.g. "None known — technique has no legitimate use
in this environment"), not left blank or omitted.

## 4. At least one test case (required)

Every rule must ship with at least one test case demonstrating a log event
that the rule should match (a true positive). Prefer a colocated file such as
`<rule_name>.test.yml` or a `tests:`/`test_cases:` block referencing sample
log data. A rule submitted without any accompanying test evidence is
incomplete.

## 5. Naming convention (required)

Rule names (the filename and the `title`-derived identifier used for the rule
ID/slug) must be lowercase with underscores, e.g. `suspicious_powershell_encoded_command`.
No spaces, hyphens, or CamelCase in the rule name/slug. The human-readable
`title` field can use normal casing/spacing — this rule applies to the
identifying name, not the display title.

## Review checklist

When reviewing a rule, check in this order and report every violation found
(don't stop at the first one):

1. Does `tags` contain at least one `attack.tXXXX` entry?
2. Is `level` one of low/medium/high/critical, and is there a justification
   for that choice somewhere in the rule?
3. Does `falsepositives` list concrete conditions (or an explicit justified
   "none known")?
4. Is there at least one test case / sample event for the rule?
5. Is the rule name lowercase_with_underscores?

Call out missing items explicitly rather than assuming they exist elsewhere.

## Automated validation

`scripts/validate-rule.py` checks a rule file against requirements 1-5 above
(ATT&CK tags, severity + justification, false positives, test case, naming)
and prints a JSON report.

```
python scripts/validate-rule.py <path-to-rule.yml>
```

It exits `0` when the rule passes every check, `1` when at least one check
fails (see the `issues` list in the output for specifics), and `2` on a
usage or parse error. Run it against any rule you write or review as a
first pass before doing a manual read-through — it does not replace manual
review of the detection logic itself, only the metadata/documentation
requirements.

## References

When writing rules, consult:
- `references/example-rules/` - Well-formatted examples to follow
- `references/severity-guide.md` - Severity level guidance
- `references/false-positive-patterns.md` - Common FP documentation
