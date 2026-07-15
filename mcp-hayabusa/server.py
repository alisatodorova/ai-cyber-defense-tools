"""MCP server that wraps Hayabusa for EVTX analysis."""

import asyncio
import json
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path

import yaml
import mcp.types as types
from mcp.server import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server

server = Server("hayabusa")

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
OUTPUT_FORMATS = ["summary", "full"]
SUMMARY_FIELDS = ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "RecordID"]
HAYABUSA_DIR = Path(__file__).resolve().parent / "hayabusa"
RULES_DIR = HAYABUSA_DIR / "rules"
SCAN_TIMEOUT_SECONDS = 600

# Our own curated Sigma rules (detection engineering knowledge base), separate from
# Hayabusa's bundled rule set under HAYABUSA_DIR.
SIGMA_RULES_DIR = Path(__file__).resolve().parent / "rules"
TECHNIQUE_TAG_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)

# Trimmed ATT&CK technique index (id -> name/description/tactics), produced by
# scripts/download_attack_data.py from the full MITRE STIX bundle.
ATTACK_TECHNIQUES_FILE = Path(__file__).resolve().parent / "attack" / "techniques.json"

# Rules at this level (or above) count toward "covered"; anything below that with
# at least one matching rule is "partial".
COVERED_MIN_LEVEL = "medium"

# Populated on first get_hayabusa_rules call; rule files don't change at runtime.
_rules_cache: list[dict] | None = None

# Populated on first Sigma resource access; rule files don't change at runtime.
_sigma_rules_cache: list[dict] | None = None

# Populated on first ATT&CK resource access; the underlying file doesn't change at runtime.
_attack_techniques_cache: dict | None = None


class HayabusaNotFoundError(RuntimeError):
    """Raised when the Hayabusa executable can't be located."""


def _find_hayabusa_binary() -> Path:
    exe_name = "hayabusa.exe" if os.name == "nt" else "hayabusa"
    candidate = HAYABUSA_DIR / exe_name
    if candidate.is_file():
        return candidate

    # The official release zip ships a version-suffixed binary name
    # (e.g. hayabusa-3.10.0-win-x64.exe), so fall back to a glob.
    pattern = "hayabusa*.exe" if os.name == "nt" else "hayabusa*"
    matches = sorted(p for p in HAYABUSA_DIR.glob(pattern) if p.is_file())
    if matches:
        return matches[0]

    raise HayabusaNotFoundError(
        f"Hayabusa executable not found in {HAYABUSA_DIR}. "
        "Run scripts/download_hayabusa.py to install it."
    )


def _run_scan_evtx(
    evtx_path: str,
    min_severity: str | None = None,
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict:
    path = Path(evtx_path)
    if not path.exists():
        raise FileNotFoundError(f"EVTX path not found: {evtx_path}")

    if min_severity is not None and min_severity not in SEVERITY_ORDER:
        raise ValueError(
            f"Invalid min_severity '{min_severity}'. Must be one of: {', '.join(SEVERITY_ORDER)}"
        )

    if output_format not in OUTPUT_FORMATS:
        raise ValueError(
            f"Invalid output_format '{output_format}'. Must be one of: {', '.join(OUTPUT_FORMATS)}"
        )

    if max_results is not None and (not isinstance(max_results, int) or max_results < 1):
        raise ValueError("max_results must be a positive integer")

    hayabusa_bin = _find_hayabusa_binary()

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "results.jsonl"
        input_flag = "-d" if path.is_dir() else "-f"
        cmd = [
            str(hayabusa_bin),
            "json-timeline",
            input_flag,
            str(path),
            "-o",
            str(output_path),
            "-L",  # JSONL-output: one JSON object per line (plain -o concatenates
                   # pretty-printed objects with no separators, which isn't valid JSON)
            "-b",  # disable-abbreviations: "Level" comes back as "informational" not
                   # "info", matching SEVERITY_ORDER (otherwise info-level findings
                   # get silently dropped by the severity filter below)
            "-w",  # no-wizard: scan for all events/alerts without prompting
            "-q",  # quiet: skip the launch banner
            "-K",  # no-color: keep stdout/stderr clean of ANSI codes
            "-C",  # clobber: overwrite the output file
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"Hayabusa scan timed out after {SCAN_TIMEOUT_SECONDS}s"
            ) from e
        except OSError as e:
            raise RuntimeError(f"Failed to execute Hayabusa at {hayabusa_bin}: {e}") from e

        if result.returncode != 0:
            raise RuntimeError(
                "Hayabusa exited with code "
                f"{result.returncode}: {result.stderr.strip() or result.stdout.strip()}"
            )

        findings = []
        if output_path.exists() and output_path.stat().st_size > 0:
            # Hayabusa writes a 0-byte file (not "[]") when there are no detections.
            try:
                with output_path.open("r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            findings.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Failed to parse Hayabusa JSON output: {e}") from e

    if min_severity:
        min_index = SEVERITY_ORDER.index(min_severity)
        findings = [
            f
            for f in findings
            if str(f.get("Level", "")).lower() in SEVERITY_ORDER
            and SEVERITY_ORDER.index(str(f.get("Level", "")).lower()) >= min_index
        ]

    if rule_filter:
        needle = rule_filter.lower()
        findings = [f for f in findings if needle in str(f.get("RuleTitle", "")).lower()]

    total_findings = len(findings)

    truncated = max_results is not None and max_results < total_findings
    if max_results is not None:
        findings = findings[:max_results]

    if output_format == "summary":
        findings = [{k: f.get(k) for k in SUMMARY_FIELDS} for f in findings]

    return {
        "evtx_path": evtx_path,
        "min_severity": min_severity,
        "rule_filter": rule_filter,
        "output_format": output_format,
        "max_results": max_results,
        "total_findings": total_findings,
        "returned_findings": len(findings),
        "truncated": truncated,
        "findings": findings,
    }


def _load_rules() -> list[dict]:
    global _rules_cache
    if _rules_cache is not None:
        return _rules_cache

    rules = []
    for path in RULES_DIR.rglob("*.yml"):
        if ".git" in path.parts or "config" in path.parts:
            continue
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict) or "detection" not in data:
            continue
        rules.append(
            {
                "title": data.get("title"),
                "id": data.get("id"),
                "level": data.get("level"),
                "status": data.get("status"),
                "ruletype": data.get("ruletype"),
                "tags": data.get("tags") or [],
                "description": data.get("description"),
                "file": str(path.relative_to(HAYABUSA_DIR)),
            }
        )

    _rules_cache = rules
    return rules


def _get_hayabusa_rules(keyword: str | None = None, max_results: int | None = None) -> dict:
    if not RULES_DIR.is_dir():
        raise HayabusaNotFoundError(
            f"Hayabusa rules directory not found at {RULES_DIR}. "
            "Run scripts/download_hayabusa.py to install it."
        )

    if max_results is not None and (not isinstance(max_results, int) or max_results < 1):
        raise ValueError("max_results must be a positive integer")

    rules = _load_rules()

    if keyword:
        needle = keyword.lower()

        def matches(rule: dict) -> bool:
            haystack = " ".join(
                str(v)
                for v in (
                    rule.get("title"),
                    rule.get("description"),
                    rule.get("id"),
                    " ".join(rule.get("tags") or []),
                )
                if v
            )
            return needle in haystack.lower()

        rules = [r for r in rules if matches(r)]

    total_rules = len(rules)
    truncated = max_results is not None and max_results < total_rules
    if max_results is not None:
        rules = rules[:max_results]

    return {
        "keyword": keyword,
        "max_results": max_results,
        "total_rules": total_rules,
        "returned_rules": len(rules),
        "truncated": truncated,
        "rules": rules,
    }


def _load_sigma_rules() -> list[dict]:
    global _sigma_rules_cache
    if _sigma_rules_cache is not None:
        return _sigma_rules_cache

    rules = []
    for path in sorted(SIGMA_RULES_DIR.rglob("*.yml")):
        try:
            raw_text = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw_text)
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(data, dict) or "detection" not in data:
            continue

        tags = data.get("tags") or []
        technique_ids = sorted(
            {
                match.group(1).upper()
                for tag in tags
                if (match := TECHNIQUE_TAG_RE.match(str(tag)))
            }
        )

        rules.append(
            {
                "name": path.stem,
                "title": data.get("title"),
                "id": data.get("id"),
                "level": data.get("level"),
                "status": data.get("status"),
                "description": data.get("description"),
                "tags": tags,
                "technique_ids": technique_ids,
                "file": str(path.relative_to(SIGMA_RULES_DIR)),
                "raw": raw_text,
            }
        )

    _sigma_rules_cache = rules
    return rules


def _list_sigma_rules_metadata() -> list[dict]:
    return [{k: v for k, v in rule.items() if k != "raw"} for rule in _load_sigma_rules()]


def _get_sigma_rule_by_name(rule_name: str) -> dict:
    for rule in _load_sigma_rules():
        if rule["name"] == rule_name:
            return rule
    raise FileNotFoundError(f"No Sigma rule named '{rule_name}' found in {SIGMA_RULES_DIR}")


def _get_sigma_rules_by_technique(technique_id: str) -> list[dict]:
    needle = technique_id.upper()
    if not needle.startswith("T"):
        needle = f"T{needle}"
    return [
        {k: v for k, v in rule.items() if k != "raw"}
        for rule in _load_sigma_rules()
        if needle in rule["technique_ids"]
    ]


def _all_known_technique_ids() -> list[str]:
    ids: set[str] = set()
    for rule in _load_sigma_rules():
        ids.update(rule["technique_ids"])
    return sorted(ids)


def _load_attack_techniques() -> dict:
    global _attack_techniques_cache
    if _attack_techniques_cache is not None:
        return _attack_techniques_cache

    if not ATTACK_TECHNIQUES_FILE.is_file():
        raise FileNotFoundError(
            f"ATT&CK technique data not found at {ATTACK_TECHNIQUES_FILE}. "
            "Run scripts/download_attack_data.py to fetch it."
        )

    with ATTACK_TECHNIQUES_FILE.open("r", encoding="utf-8") as f:
        _attack_techniques_cache = json.load(f)
    return _attack_techniques_cache


def _assess_coverage(rules: list[dict]) -> str:
    if not rules:
        return "gap"

    min_index = SEVERITY_ORDER.index(COVERED_MIN_LEVEL)
    for rule in rules:
        level = str(rule.get("level") or "").lower()
        if level in SEVERITY_ORDER and SEVERITY_ORDER.index(level) >= min_index:
            return "covered"

    return "partial"


def _get_attack_technique(technique_id: str) -> dict:
    normalized = technique_id.upper()
    if not normalized.startswith("T"):
        normalized = f"T{normalized}"

    techniques = _load_attack_techniques()
    technique = techniques.get(normalized)
    if technique is None:
        raise FileNotFoundError(f"Unknown ATT&CK technique id: {technique_id}")

    detecting_rules = _get_sigma_rules_by_technique(normalized)

    return {
        "technique_id": normalized,
        "name": technique["name"],
        "description": technique["description"],
        "tactics": technique["tactics"],
        "detecting_rules": detecting_rules,
        "coverage": _assess_coverage(detecting_rules),
    }


def _analyze_coverage(technique_id: str | None = None, tactic: str | None = None) -> dict:
    if bool(technique_id) == bool(tactic):
        raise ValueError("Provide exactly one of technique_id or tactic")

    techniques_data = _load_attack_techniques()

    if technique_id:
        normalized = technique_id.upper()
        if not normalized.startswith("T"):
            normalized = f"T{normalized}"
        technique = techniques_data.get(normalized)
        if technique is None:
            raise FileNotFoundError(f"Unknown ATT&CK technique id: {technique_id}")
        candidates = [technique]
        query = {"technique_id": normalized}
    else:
        normalized_tactic = tactic.strip().lower().replace(" ", "-").replace("_", "-")
        candidates = [
            t
            for t in techniques_data.values()
            if normalized_tactic in [tac.lower() for tac in (t.get("tactics") or [])]
        ]
        if not candidates:
            known_tactics = sorted(
                {tac for t in techniques_data.values() for tac in (t.get("tactics") or [])}
            )
            raise ValueError(
                f"No ATT&CK techniques found for tactic '{tactic}'. "
                f"Known tactics: {', '.join(known_tactics)}"
            )
        candidates.sort(key=lambda t: t["technique_id"])
        query = {"tactic": normalized_tactic}

    techniques = []
    for t in candidates:
        detecting_rules = _get_sigma_rules_by_technique(t["technique_id"])
        techniques.append(
            {
                "technique_id": t["technique_id"],
                "name": t["name"],
                "tactics": t.get("tactics") or [],
                "coverage": _assess_coverage(detecting_rules),
                "detecting_rules": [
                    {"name": r["name"], "title": r["title"], "level": r["level"]}
                    for r in detecting_rules
                ],
            }
        )

    coverage_summary = {"covered": 0, "partial": 0, "gap": 0}
    for t in techniques:
        coverage_summary[t["coverage"]] += 1

    gaps = [
        {"technique_id": t["technique_id"], "name": t["name"]}
        for t in techniques
        if t["coverage"] == "gap"
    ]

    return {
        "query": query,
        "total_techniques": len(techniques),
        "coverage_summary": coverage_summary,
        "gaps": gaps,
        "techniques": techniques,
    }


def _load_hayabusa_rule_yaml(hayabusa_candidate: dict) -> dict | None:
    path = HAYABUSA_DIR / hayabusa_candidate["file"]
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return data if isinstance(data, dict) else None


def _slugify_category(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_") or "process_creation"


def _create_rule_template(
    normalized_technique_id: str, technique: dict, hayabusa_candidate: dict | None
) -> tuple[Path, bool]:
    hayabusa_yaml = _load_hayabusa_rule_yaml(hayabusa_candidate) if hayabusa_candidate else None

    detection = hayabusa_yaml.get("detection") if hayabusa_yaml else None
    if not isinstance(detection, dict):
        detection = {"selection": {"CommandLine|contains": "REPLACE_ME"}, "condition": "selection"}

    # Carry over the candidate's real logsource (category or service, e.g. "security") rather
    # than guessing one from its file path — that's what determines the actual log channel.
    source_logsource = hayabusa_yaml.get("logsource") if hayabusa_yaml else None
    if isinstance(source_logsource, dict) and source_logsource:
        logsource = dict(source_logsource)
        category = _slugify_category(
            str(source_logsource.get("category") or source_logsource.get("service") or "process_creation")
        )
    else:
        logsource = {"category": "process_creation", "product": "windows"}
        category = "process_creation"

    target_dir = SIGMA_RULES_DIR / category
    filename = f"{category}_win_{normalized_technique_id.lower().replace('.', '_')}_gap_template.yml"
    target_path = target_dir / filename

    if target_path.exists():
        return target_path, False

    tags = [f"attack.{tac}" for tac in (technique.get("tactics") or [])]
    tags.append(f"attack.{normalized_technique_id.lower()}")

    if hayabusa_candidate:
        title = f"{hayabusa_candidate['title']} (Adapted for Gap Coverage)"
        description = (
            f"Template generated to close the detection gap for ATT&CK technique "
            f"{normalized_technique_id} ({technique['name']}). Detection logic seeded from "
            f"Hayabusa bundled rule '{hayabusa_candidate['title']}' ({hayabusa_candidate['file']}) "
            "— review and adapt before enabling."
        )
        level = hayabusa_candidate.get("level") or "medium"
    else:
        title = f"Potential {technique['name']} Activity"
        description = (
            f"Template generated to close the detection gap for ATT&CK technique "
            f"{normalized_technique_id} ({technique['name']}). No existing curated or Hayabusa-"
            "bundled rule targets this technique, so the detection logic below is a placeholder "
            "and must be authored from scratch based on the technique's behavior."
        )
        level = "medium"

    rule = {
        "title": title,
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": description,
        "references": [
            f"https://attack.mitre.org/techniques/{normalized_technique_id.replace('.', '/')}/"
        ],
        "tags": tags,
        "logsource": logsource,
        "detection": detection,
        "level": level,
        "falsepositives": ["Unknown"],
    }

    target_dir.mkdir(parents=True, exist_ok=True)
    header = (
        f"# GENERATED TEMPLATE - gap-fill for {normalized_technique_id} ({technique['name']}).\n"
        "# Review detection logic, tune fields, and remove this header before treating as final.\n"
    )
    target_path.write_text(
        header + yaml.safe_dump(rule, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return target_path, True


def _suggest_rule(technique_id: str, create_template: bool = False) -> dict:
    techniques_data = _load_attack_techniques()
    normalized = technique_id.upper()
    if not normalized.startswith("T"):
        normalized = f"T{normalized}"

    technique = techniques_data.get(normalized)
    if technique is None:
        raise FileNotFoundError(f"Unknown ATT&CK technique id: {technique_id}")

    existing_rules = _get_sigma_rules_by_technique(normalized)
    coverage = _assess_coverage(existing_rules)

    result = {
        "technique_id": normalized,
        "name": technique["name"],
        "tactics": technique.get("tactics") or [],
        "existing_coverage": {"status": coverage, "rules": existing_rules},
    }

    if coverage == "covered":
        result["suggestion"] = None
        result["message"] = (
            f"{normalized} is already covered by {len(existing_rules)} rule(s) in rules/. "
            "No suggestion needed."
        )
        return result

    needle = f"attack.{normalized.lower()}"
    hayabusa_candidates = [
        rule
        for rule in _load_rules()
        if any(str(tag).lower() == needle for tag in (rule.get("tags") or []))
    ]
    level_rank = {level: i for i, level in enumerate(SEVERITY_ORDER)}

    def _candidate_rank(r: dict) -> tuple:
        not_deprecated = str(r.get("status") or "").lower() != "deprecated"
        is_stable = str(r.get("status") or "").lower() == "stable"
        level = level_rank.get(str(r.get("level") or "").lower(), -1)
        return (not_deprecated, level, is_stable)

    hayabusa_candidates.sort(key=_candidate_rank, reverse=True)
    best_candidate = hayabusa_candidates[0] if hayabusa_candidates else None

    if best_candidate:
        guidance = (
            f"Hayabusa's bundled rule set already has {len(hayabusa_candidates)} rule(s) tagged "
            f"{normalized}. Recommend adapting the highest-severity one "
            f"('{best_candidate['title']}', level={best_candidate['level']}) into rules/ rather "
            "than writing a detection from scratch."
        )
    else:
        guidance = (
            f"No existing rule (curated or Hayabusa-bundled) targets {normalized} directly. "
            f"This is a genuine detection gap for '{technique['name']}' "
            f"({', '.join(technique.get('tactics') or [])}). A new Sigma rule needs to be "
            "authored based on the technique's behavior."
        )

    result["suggestion"] = {
        "approach": "promote_existing" if best_candidate else "write_new",
        "hayabusa_candidates": hayabusa_candidates[:5],
        "guidance": guidance,
    }

    if create_template:
        target_path, created = _create_rule_template(normalized, technique, best_candidate)
        result["template"] = {
            "path": str(target_path.relative_to(SIGMA_RULES_DIR.parent)),
            "created": created,
        }
        if created:
            global _sigma_rules_cache
            _sigma_rules_cache = None

    return result


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="scan_evtx",
            description="Scan an EVTX file (or directory of EVTX files) with Hayabusa.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evtx_path": {
                        "type": "string",
                        "description": "Path to an .evtx file or a directory containing .evtx files.",
                    },
                    "min_severity": {
                        "type": "string",
                        "description": "Optional minimum severity to include.",
                        "enum": SEVERITY_ORDER,
                    },
                    "rule_filter": {
                        "type": "string",
                        "description": "Only include findings whose rule title contains this "
                        "string (case-insensitive), e.g. 'lateral' or 'mimikatz'.",
                    },
                    "output_format": {
                        "type": "string",
                        "description": "'summary' returns a condensed set of fields per finding; "
                        "'full' returns everything Hayabusa reported.",
                        "enum": OUTPUT_FORMATS,
                        "default": "summary",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of findings to return.",
                        "minimum": 1,
                    },
                },
                "required": ["evtx_path"],
            },
        ),
        types.Tool(
            name="get_hayabusa_rules",
            description="List available Hayabusa detection rules, optionally filtered by keyword. "
            "Useful for seeing what rules exist before running scan_evtx.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Only include rules whose title, description, id, or tags "
                        "contain this string (case-insensitive), e.g. 'lateral' or 'mimikatz'.",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of rules to return.",
                        "minimum": 1,
                    },
                },
            },
        ),
        types.Tool(
            name="analyze_coverage",
            description="Analyze ATT&CK detection coverage for a specific technique or an entire "
            "tactic, using our Sigma rule knowledge base. Returns per-technique covered/partial/gap "
            "status plus a summary and a list of gaps.",
            inputSchema={
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "ATT&CK technique ID to analyze, e.g. 'T1003.001'. "
                        "Provide this or 'tactic', not both.",
                    },
                    "tactic": {
                        "type": "string",
                        "description": "ATT&CK tactic name to analyze all its techniques, e.g. "
                        "'credential-access' or 'Credential Access'. Provide this or "
                        "'technique_id', not both.",
                    },
                },
            },
        ),
        types.Tool(
            name="suggest_rule",
            description="Check whether an ATT&CK technique is already covered by our curated rules. "
            "If it's a gap, suggest a detection approach — promoting a matching Hayabusa bundled "
            "rule if one exists, or drafting a new one. Optionally writes a starter Sigma rule "
            "template into rules/.",
            inputSchema={
                "type": "object",
                "properties": {
                    "technique_id": {
                        "type": "string",
                        "description": "ATT&CK technique ID to check/suggest for, e.g. 'T1003.006'.",
                    },
                    "create_template": {
                        "type": "boolean",
                        "description": "If true and the technique is a coverage gap, write a "
                        "starter Sigma rule template into rules/ (seeded from a matching Hayabusa "
                        "rule when one exists).",
                        "default": False,
                    },
                },
                "required": ["technique_id"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "scan_evtx":
        evtx_path = arguments.get("evtx_path")
        if not evtx_path:
            payload = {"error": "invalid_argument", "message": "evtx_path is required"}
            return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]

        min_severity = arguments.get("min_severity")
        rule_filter = arguments.get("rule_filter")
        output_format = arguments.get("output_format", "summary")
        max_results = arguments.get("max_results")

        try:
            payload = await asyncio.to_thread(
                _run_scan_evtx, evtx_path, min_severity, rule_filter, output_format, max_results
            )
        except HayabusaNotFoundError as e:
            payload = {"error": "hayabusa_not_found", "message": str(e)}
        except FileNotFoundError as e:
            payload = {"error": "file_not_found", "message": str(e)}
        except ValueError as e:
            payload = {"error": "invalid_argument", "message": str(e)}
        except RuntimeError as e:
            payload = {"error": "scan_failed", "message": str(e)}

    elif name == "get_hayabusa_rules":
        keyword = arguments.get("keyword")
        max_results = arguments.get("max_results")

        try:
            payload = await asyncio.to_thread(_get_hayabusa_rules, keyword, max_results)
        except HayabusaNotFoundError as e:
            payload = {"error": "hayabusa_not_found", "message": str(e)}
        except ValueError as e:
            payload = {"error": "invalid_argument", "message": str(e)}

    elif name == "analyze_coverage":
        technique_id = arguments.get("technique_id")
        tactic = arguments.get("tactic")

        try:
            payload = await asyncio.to_thread(_analyze_coverage, technique_id, tactic)
        except FileNotFoundError as e:
            payload = {"error": "not_found", "message": str(e)}
        except ValueError as e:
            payload = {"error": "invalid_argument", "message": str(e)}

    elif name == "suggest_rule":
        technique_id = arguments.get("technique_id")
        if not technique_id:
            payload = {"error": "invalid_argument", "message": "technique_id is required"}
        else:
            create_template = bool(arguments.get("create_template", False))
            try:
                payload = await asyncio.to_thread(_suggest_rule, technique_id, create_template)
            except FileNotFoundError as e:
                payload = {"error": "not_found", "message": str(e)}
            except ValueError as e:
                payload = {"error": "invalid_argument", "message": str(e)}

    else:
        raise ValueError(f"Unknown tool: {name}")

    return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]


@server.list_resources()
async def list_resources() -> list[types.Resource]:
    rules = _load_sigma_rules()

    resources = [
        types.Resource(
            uri="detection://rules",
            name="All Sigma rules",
            description="Metadata for every Sigma detection rule in the knowledge base.",
            mimeType="application/json",
        )
    ]

    for rule in rules:
        resources.append(
            types.Resource(
                uri=f"detection://rules/{rule['name']}",
                name=rule["title"] or rule["name"],
                description=rule["description"] or f"Sigma rule: {rule['name']}",
                mimeType="text/yaml",
            )
        )

    for technique_id in _all_known_technique_ids():
        resources.append(
            types.Resource(
                uri=f"detection://rules/by-technique/{technique_id}",
                name=f"Rules for {technique_id}",
                description=f"Sigma rules mapped to ATT&CK technique {technique_id}.",
                mimeType="application/json",
            )
        )
        resources.append(
            types.Resource(
                uri=f"detection://attack/techniques/{technique_id}",
                name=f"ATT&CK coverage: {technique_id}",
                description=f"Technique details and detection coverage for {technique_id}.",
                mimeType="application/json",
            )
        )

    return resources


@server.list_resource_templates()
async def list_resource_templates() -> list[types.ResourceTemplate]:
    return [
        types.ResourceTemplate(
            uriTemplate="detection://rules/{rule_name}",
            name="Sigma rule by name",
            description="Raw YAML content of a specific Sigma rule, addressed by its file stem.",
            mimeType="text/yaml",
        ),
        types.ResourceTemplate(
            uriTemplate="detection://rules/by-technique/{technique_id}",
            name="Sigma rules by ATT&CK technique",
            description="Metadata for Sigma rules mapped to a given ATT&CK technique ID (e.g. T1003.001).",
            mimeType="application/json",
        ),
        types.ResourceTemplate(
            uriTemplate="detection://attack/techniques/{technique_id}",
            name="ATT&CK technique coverage",
            description="Technique name/description, our detecting rules, and a covered/partial/gap "
            "coverage assessment for a given ATT&CK technique ID (e.g. T1003.001).",
            mimeType="application/json",
        ),
    ]


@server.read_resource()
async def read_resource(uri) -> list[ReadResourceContents]:
    uri_str = str(uri)

    if uri_str.startswith("detection://attack/techniques/"):
        technique_id = uri_str[len("detection://attack/techniques/") :]
        if not technique_id:
            raise ValueError("technique_id is required in detection://attack/techniques/{technique_id}")
        technique = await asyncio.to_thread(_get_attack_technique, technique_id)
        return [ReadResourceContents(content=json.dumps(technique, indent=2), mime_type="application/json")]

    if not uri_str.startswith("detection://rules"):
        raise ValueError(f"Unknown resource: {uri_str}")

    remainder = uri_str[len("detection://rules") :].lstrip("/")

    if not remainder:
        payload = json.dumps(_list_sigma_rules_metadata(), indent=2)
        return [ReadResourceContents(content=payload, mime_type="application/json")]

    if remainder.startswith("by-technique/"):
        technique_id = remainder[len("by-technique/") :]
        if not technique_id:
            raise ValueError("technique_id is required in detection://rules/by-technique/{technique_id}")
        payload = json.dumps(_get_sigma_rules_by_technique(technique_id), indent=2)
        return [ReadResourceContents(content=payload, mime_type="application/json")]

    rule_name = remainder
    rule = await asyncio.to_thread(_get_sigma_rule_by_name, rule_name)
    return [ReadResourceContents(content=rule["raw"], mime_type="text/yaml")]


async def run() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
