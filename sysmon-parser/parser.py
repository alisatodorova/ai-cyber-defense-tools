#!/usr/bin/env python3
"""Extract key fields from a Sysmon Event ID 1 (Process Creation) XML file."""

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

FIELDS = [
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Hashes",
]

CSV_FIELDS = [
    "EventID",
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Computer",
    "Hashes",
]


def parse_event(event_el):
    system = event_el.find("e:System", NS)
    event_data = event_el.find("e:EventData", NS)

    result = {
        "EventID": system.findtext("e:EventID", namespaces=NS),
        "Computer": system.findtext("e:Computer", namespaces=NS),
    }

    data_by_name = {
        data.get("Name"): data.text for data in event_data.findall("e:Data", NS)
    }
    for field in FIELDS:
        result[field] = data_by_name.get(field)

    return result


def matches_filters(event, args):
    if args.image and args.image.lower() not in (event.get("Image") or "").lower():
        return False
    if args.user and event.get("User") != args.user:
        return False
    if args.integrity_level and (
        (event.get("IntegrityLevel") or "").lower() != args.integrity_level.lower()
    ):
        return False
    if args.command_line:
        command_line = (event.get("CommandLine") or "").lower()
        if not any(substr.lower() in command_line for substr in args.command_line):
            return False
    return True


def parse_file(xml_path, args):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    tag = root.tag.split("}")[-1]
    if tag == "Events":
        events = [parse_event(event_el) for event_el in root.findall("e:Event", NS)]
        is_multi = True
    else:
        events = [parse_event(root)]
        is_multi = False

    events = [event for event in events if matches_filters(event, args)]
    return events, is_multi


def output_json(events, is_multi):
    if is_multi:
        print(json.dumps(events, indent=2))
    else:
        print(json.dumps(events[0] if events else None, indent=2))


def output_jsonl(events):
    for event in events:
        print(json.dumps(event))


def output_csv(events):
    writer = csv.DictWriter(sys.stdout, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for event in events:
        writer.writerow(event)


# This stats feature is for quick triage to understand what's in a file before deep analysis
def compute_stats(events):
    images = sorted({event.get("Image") for event in events if event.get("Image")})
    users = sorted({event.get("User") for event in events if event.get("User")})

    integrity_counts = {}
    for event in events:
        level = event.get("IntegrityLevel") or "Unknown"
        integrity_counts[level] = integrity_counts.get(level, 0) + 1

    return {
        "TotalEvents": len(events),
        "UniqueProcessCount": len(images),
        "UniqueProcesses": images,
        "UniqueUserCount": len(users),
        "UniqueUsers": users,
        "EventsByIntegrityLevel": integrity_counts,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract key fields from Sysmon Event ID 1 XML."
    )
    parser.add_argument("xml_path", help="Path to a Sysmon event XML file")
    parser.add_argument(
        "--image", help="Filter: Image field contains this substring"
    )
    parser.add_argument("--user", help="Filter: User field exact match")
    parser.add_argument(
        "--integrity-level",
        help="Filter: IntegrityLevel exact match (High, Medium, Low, System)",
    )
    parser.add_argument(
        "--command-line",
        action="append",
        dest="command_line",
        help=(
            "Filter: CommandLine contains this substring (repeatable; OR'd "
            "together). Values starting with '-' need the equals form, e.g. "
            "--command-line=-enc"
        ),
    )
    parser.add_argument(
        "--format",
        choices=["json", "jsonl", "csv"],
        default="json",
        help=(
            "Output format: json (default, array or single object matching "
            "input shape), jsonl (one JSON object per line), or csv (with "
            "headers)"
        ),
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help=(
            "Print summary statistics (total events, unique processes/users, "
            "counts by IntegrityLevel) instead of the events themselves. "
            "Applies after any filters; ignores --format."
        ),
    )
    return parser.parse_args()


def main():
    args = parse_args()
    events, is_multi = parse_file(args.xml_path, args)

    if args.stats:
        print(json.dumps(compute_stats(events), indent=2))
    elif args.format == "jsonl":
        output_jsonl(events)
    elif args.format == "csv":
        output_csv(events)
    else:
        output_json(events, is_multi)


if __name__ == "__main__":
    main()
