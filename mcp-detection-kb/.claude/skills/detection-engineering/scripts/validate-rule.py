#!/usr/bin/env python3
"""Validate a Sigma detection rule against the detection-engineering skill standards.

Usage:
    python validate-rule.py <path-to-rule.yml>

Prints a JSON report to stdout and exits 0 if the rule passes all checks,
1 if any check fails, 2 on a usage/parse error.
"""

import json
import os
import re
import sys

import yaml

ATTACK_TAG_RE = re.compile(r'^attack\.t\d{4}(\.\d{3})?$')
VALID_LEVELS = {'low', 'medium', 'high', 'critical'}
NAME_RE = re.compile(r'^[a-z0-9]+(_[a-z0-9]+)*$')


def load_rule(path):
    with open(path, 'r', encoding='utf-8') as f:
        raw_text = f.read()
    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        raise ValueError(f'Failed to parse YAML: {e}')
    if not isinstance(data, dict):
        raise ValueError('Rule file does not contain a YAML mapping at the top level')
    return data, raw_text


def check_attack_tags(rule):
    tags = rule.get('tags') or []
    if not isinstance(tags, list):
        return False, [], ['`tags` field is present but is not a list']
    matched = [t for t in tags if isinstance(t, str) and ATTACK_TAG_RE.match(t)]
    if matched:
        return True, matched, []
    return False, [], [
        'No ATT&CK technique tag found in `tags` (expected an entry matching '
        '`attack.tXXXX` or `attack.tXXXX.YYY`)'
    ]


def check_severity(rule, raw_text):
    issues = []
    level = rule.get('level')
    level_valid = isinstance(level, str) and level.strip().lower() in VALID_LEVELS
    if level is None:
        issues.append('`level` field is missing')
    elif not level_valid:
        issues.append(f'`level` value {level!r} is not one of {sorted(VALID_LEVELS)}')

    description = rule.get('description')
    has_description_justification = isinstance(description, str) and len(description.strip()) > 20
    has_severity_comment = bool(re.search(r'#\s*Severity:', raw_text, re.IGNORECASE))
    has_justification = has_description_justification or has_severity_comment
    if not has_justification:
        issues.append(
            'No severity justification found (expected a substantive `description` '
            'field or a `# Severity:` comment above `level`)'
        )

    passed = level_valid and has_justification
    return passed, issues


def check_falsepositives(rule):
    issues = []
    fps = rule.get('falsepositives')
    if not fps:
        issues.append('`falsepositives` field is missing or empty')
        return False, issues
    if not isinstance(fps, list):
        fps = [fps]
    cleaned = [str(x).strip() for x in fps if str(x).strip()]
    if not cleaned:
        issues.append('`falsepositives` field is present but has no content')
        return False, issues
    if len(cleaned) == 1 and cleaned[0].lower() in {'unknown', 'none', 'n/a'}:
        issues.append(
            "`falsepositives` contains only an unqualified 'Unknown'/'None' — "
            'must list concrete conditions or an explicitly justified "none known"'
        )
        return False, issues
    return True, issues


def check_test_case(rule_path, rule):
    issues = []
    base, _ = os.path.splitext(rule_path)
    test_path = f'{base}.test.yml'

    if os.path.isfile(test_path):
        try:
            with open(test_path, 'r', encoding='utf-8') as f:
                test_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            issues.append(f'Colocated test file {os.path.basename(test_path)} failed to parse: {e}')
            return False, issues

        tests = None
        if isinstance(test_data, dict):
            tests = test_data.get('tests') or test_data.get('test_cases')
        if isinstance(tests, list) and len(tests) > 0:
            return True, issues
        issues.append(
            f'Colocated test file {os.path.basename(test_path)} exists but has no '
            '`tests`/`test_cases` entries'
        )
        return False, issues

    # Fall back to an inline tests:/test_cases: block within the rule itself.
    inline_tests = rule.get('tests') or rule.get('test_cases')
    if isinstance(inline_tests, list) and len(inline_tests) > 0:
        return True, issues

    issues.append(
        f'No test evidence found: expected a colocated `{os.path.basename(test_path)}` '
        'file or an inline `tests`/`test_cases` block'
    )
    return False, issues


def check_naming(rule_path, rule):
    issues = []
    filename = os.path.splitext(os.path.basename(rule_path))[0]
    if filename.endswith('.test'):
        filename = filename[: -len('.test')]

    filename_valid = bool(NAME_RE.match(filename))
    if not filename_valid:
        issues.append(
            f'Rule filename slug {filename!r} is not lowercase_with_underscores '
            '(no spaces, hyphens, or CamelCase allowed)'
        )
    return filename_valid, issues


def validate(rule_path):
    result = {
        'file': rule_path,
        'valid': False,
        'checks': {},
        'issues': [],
    }

    if not os.path.isfile(rule_path):
        result['issues'].append(f'File not found: {rule_path}')
        return result

    try:
        rule, raw_text = load_rule(rule_path)
    except ValueError as e:
        result['issues'].append(str(e))
        return result

    attack_ok, matched_tags, attack_issues = check_attack_tags(rule)
    result['checks']['attack_tags'] = {
        'passed': attack_ok,
        'matched_tags': matched_tags,
    }
    result['issues'].extend(attack_issues)

    severity_ok, severity_issues = check_severity(rule, raw_text)
    result['checks']['severity'] = {
        'passed': severity_ok,
        'level': rule.get('level'),
    }
    result['issues'].extend(severity_issues)

    fp_ok, fp_issues = check_falsepositives(rule)
    result['checks']['falsepositives'] = {'passed': fp_ok}
    result['issues'].extend(fp_issues)

    test_ok, test_issues = check_test_case(rule_path, rule)
    result['checks']['test_case'] = {'passed': test_ok}
    result['issues'].extend(test_issues)

    naming_ok, naming_issues = check_naming(rule_path, rule)
    result['checks']['naming'] = {'passed': naming_ok}
    result['issues'].extend(naming_issues)

    result['valid'] = all(
        c['passed'] for c in result['checks'].values()
    )
    return result


def main():
    if len(sys.argv) != 2:
        print(json.dumps({'error': 'Usage: validate-rule.py <path-to-rule.yml>'}), file=sys.stderr)
        sys.exit(2)

    rule_path = sys.argv[1]
    result = validate(rule_path)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result['valid'] else 1)


if __name__ == '__main__':
    main()
