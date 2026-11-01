#!/usr/bin/env python3
"""Aggregate Xtate NDJSON events into one record per target/port.

This is a post-processing example, not part of the scanner. It uses only the
Python standard library and streams the input line by line.

Example:
    xtate ... -output-module ndjson -output-file scan.jsonl
    python scripts/aggregate-events.py scan.jsonl -o per-target.jsonl --stats

The input schema is Xtate's NDJSON output. Common fields are used for grouping;
module-specific scan_report/probe_report/output_report objects are preserved by
merging each object's fields (last non-empty value wins).
"""

import argparse
import csv
import json
import sys
import time


STATUS_PRIORITY = {
    "open": 50,
    "fake-open": 40,
    "responsed": 30,
    "acknowledged": 20,
    "closed": 10,
}

DEFAULT_GROUP_FIELDS = ("ip_proto", "ip_them", "port_them")


def _merge_object(dst, src):
    """Merge a module report object without assuming a module-specific schema."""
    if not isinstance(src, dict):
        return
    for key, value in src.items():
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            # Keep structured values intact. For repeated occurrences, the last
            # non-empty value is used; consumers that need every value should
            # retain the raw NDJSON stream.
            dst[key] = value
        elif value != "":
            dst[key] = value


def _new_group(first, group_fields):
    group = {name: first.get(name) for name in group_fields}
    group.update({
        "status": None,
        "status_reason": None,
        "events": 0,
        "first_seen": None,
        "last_seen": None,
        "levels": {},
        "classifications": {},
        "reasons": {},
        "scan_report": {},
        "probe_report": {},
        "output_report": {},
        "group_fields": list(group_fields),
    })
    return group


def _bump(counter, key):
    if key is None:
        key = ""
    counter[key] = counter.get(key, 0) + 1


def aggregate_lines(lines, group_fields, strict=False):
    groups = {}
    events = 0
    bad = 0

    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            bad += 1
            if strict:
                raise SystemExit("bad JSON on line %d: %s" % (lineno, exc))
            print("skip bad JSON on line %d: %s" % (lineno, exc),
                  file=sys.stderr)
            continue
        if not isinstance(event, dict):
            bad += 1
            if strict:
                raise SystemExit("non-object JSON on line %d" % lineno)
            continue

        key = tuple(event.get(name) for name in group_fields)
        group = groups.get(key)
        if group is None:
            group = _new_group(event, group_fields)
            groups[key] = group

        events += 1
        group["events"] += 1
        timestamp = event.get("time")
        if timestamp:
            if group["first_seen"] is None or timestamp < group["first_seen"]:
                group["first_seen"] = timestamp
            if group["last_seen"] is None or timestamp > group["last_seen"]:
                group["last_seen"] = timestamp

        classification = event.get("classification")
        reason = event.get("reason")
        _bump(group["classifications"], classification)
        _bump(group["reasons"], reason)
        _bump(group["levels"], event.get("level"))

        old = group["status"]
        if classification is not None:
            if old is None or STATUS_PRIORITY.get(
                    classification, 0) >= STATUS_PRIORITY.get(old, 0):
                group["status"] = classification
                group["status_reason"] = reason

        _merge_object(group["scan_report"], event.get("scan_report"))
        _merge_object(group["probe_report"], event.get("probe_report"))
        _merge_object(group["output_report"], event.get("output_report"))

    return groups, events, bad


def emit_jsonl(groups, out):
    for group in groups.values():
        out.write(json.dumps(group, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")))
        out.write("\n")


def emit_json(groups, out):
    json.dump(list(groups.values()), out, ensure_ascii=False, sort_keys=True,
              indent=2)
    out.write("\n")


def emit_csv(groups, out):
    fields = ["ip_proto", "ip_them", "port_them", "status", "status_reason",
              "events", "first_seen", "last_seen", "levels", "classifications",
              "reasons", "scan_report", "probe_report", "output_report"]
    writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for group in groups.values():
        row = dict(group)
        for name in ("levels", "classifications", "reasons", "scan_report",
                     "probe_report", "output_report"):
            row[name] = json.dumps(row[name], ensure_ascii=False,
                                   separators=(",", ":"))
        writer.writerow(row)



def _maxrss_kb():
    """Return peak RSS in KiB when the platform exposes it."""
    try:
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            value //= 1024
        return value
    except (ImportError, AttributeError):
        pass


    return None

def main():
    ap = argparse.ArgumentParser(
        description="Aggregate Xtate NDJSON events per target/port.")
    ap.add_argument("input", help="NDJSON file, or - for stdin")
    ap.add_argument("-o", "--output", default="-",
                    help="output file, or - for stdout (default)")
    ap.add_argument("--format", choices=("jsonl", "json", "csv"),
                    default="jsonl", help="output format (default jsonl)")
    ap.add_argument("--group-by",
                    default=",".join(DEFAULT_GROUP_FIELDS),
                    help="comma-separated grouping fields (default: "
                         "ip_proto,ip_them,port_them)")
    ap.add_argument("--strict", action="store_true",
                    help="abort on malformed JSON instead of skipping it")
    ap.add_argument("--stats", action="store_true",
                    help="print input/output counts and timing to stderr")
    args = ap.parse_args()

    group_fields = tuple(x.strip() for x in args.group_by.split(",") if x.strip())
    if not group_fields:
        raise SystemExit("--group-by must contain at least one field")

    start = time.perf_counter()
    if args.input == "-":
        fh = sys.stdin
        close_input = False
    else:
        fh = open(args.input, encoding="utf-8")
        close_input = True

    try:
        groups, events, bad = aggregate_lines(fh, group_fields, args.strict)
    finally:
        if close_input:
            fh.close()

    if args.output == "-":
        out = sys.stdout
        close_output = False
    else:
        out = open(args.output, "w", encoding="utf-8", newline="")
        close_output = True
    try:
        if args.format == "jsonl":
            emit_jsonl(groups, out)
        elif args.format == "json":
            emit_json(groups, out)
        else:
            emit_csv(groups, out)
    finally:
        if close_output:
            out.close()

    elapsed = time.perf_counter() - start
    if args.stats:
        maxrss = _maxrss_kb()
        print("input_events=%d groups=%d bad_json=%d elapsed=%.3fs%s" % (
            events, len(groups), bad, elapsed,
            "" if maxrss is None else " maxrss_kb=%d" % maxrss),
            file=sys.stderr)


if __name__ == "__main__":
    main()
