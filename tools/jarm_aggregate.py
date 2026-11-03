#!/usr/bin/env python3
"""Aggregate JARM parts emitted by Xtate's stateless `jarm` probe.

The scanner deliberately keeps no per-target group state.  Each of the ten
probe slots emits one OutItem with:

    probe report.jarm_slot  1..10
    probe report.jarm_slots 10
    probe report.jarm_part  "cipher|version|extensions"

This tool groups those rows by (ip_them, port_them), reports completeness,
computes a JARM-style hash from all ten parts, and writes a retry list for
targets that are missing slots.

This is an output-side post-processor: it is not part of the scanner hot path.
"""
import argparse
import hashlib
import json
import sys
from collections import defaultdict


def report_of(record):
    return record.get("probe report") or record.get("probe_report") or {}


def target_of(record):
    ip = record.get("ip_them", record.get("ip"))
    port = record.get("port_them", record.get("port"))
    return ip, port


def part_of(record):
    report = report_of(record)
    part = report.get("jarm_part", report.get("fingerprint"))
    slot = report.get("jarm_slot", report.get("jarm_index", report.get("index")))
    return slot, part


def read_records(paths):
    for path in paths:
        if path == "-":
            stream = sys.stdin
            close = False
        else:
            stream = open(path, "r", encoding="utf-8")
            close = True
        try:
            for line_no, line in enumerate(stream, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    sys.stderr.write(f"{path}:{line_no}: invalid JSON: {exc}\n")
                    yield None
        finally:
            if close:
                stream.close()


def jarm_hash(parts, slots):
    """Build the standard 62-character JARM fingerprint.

    The first 30 hex characters hash the ten concatenated
    ``cipher|version`` fields; the last 32 hash the ten concatenated
    extension fields. Missing slots contribute the conventional ``|||``.
    """
    cipher_version = []
    extensions = []
    for slot in range(1, slots + 1):
        part = parts.get(slot, "|||")
        fields = part.split("|", 2)
        cipher_version.append("|".join(fields[:2]))
        extensions.append(fields[2] if len(fields) == 3 else "")
    first = hashlib.sha256("".join(cipher_version).encode("utf-8")).hexdigest()[:30]
    second = hashlib.sha256("".join(extensions).encode("utf-8")).hexdigest()[:32]
    raw = "".join(parts.get(i, "|||") for i in range(1, slots + 1))
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return digest, first + second


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", default=["-"],
                        help="NDJSON input files, or - for stdin")
    parser.add_argument("--slots", type=int, default=10,
                        help="number of JARM slots (default: 10)")
    parser.add_argument("--complete-out", metavar="FILE",
                        help="write one aggregate JSON object per complete target")
    parser.add_argument("--retry-out", metavar="FILE",
                        help="write one JSON object per incomplete target")
    parser.add_argument("--retry-csv", metavar="FILE",
                        help="write incomplete targets as ip_them,port_them,missing_slots")
    parser.add_argument("--retry-ip-file", metavar="FILE",
                        help="write unique incomplete ip_them addresses")
    parser.add_argument("--stats-out", metavar="FILE",
                        help="write aggregate statistics as JSON")
    args = parser.parse_args(argv)

    if args.slots < 1:
        parser.error("--slots must be positive")

    groups = defaultdict(dict)
    duplicate_slots = 0
    invalid_records = 0
    records = 0

    for record in read_records(args.inputs):
        records += 1
        if record is None:
            invalid_records += 1
            continue
        ip, port = target_of(record)
        slot, part = part_of(record)
        if ip is None or port is None or part is None:
            invalid_records += 1
            continue
        try:
            slot = int(slot)
        except (TypeError, ValueError):
            invalid_records += 1
            continue
        if not (1 <= slot <= args.slots):
            invalid_records += 1
            continue
        key = (str(ip), int(port))
        if slot in groups[key]:
            duplicate_slots += 1
        groups[key][slot] = str(part)

    complete = []
    retry = []
    missing_hist = defaultdict(int)
    jarm_counts = defaultdict(int)

    for (ip, port), parts in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1])):
        missing = [slot for slot in range(1, args.slots + 1) if slot not in parts]
        if missing:
            retry.append({
                "ip_them": ip,
                "port_them": port,
                "slots_seen": len(parts),
                "slots": args.slots,
                "missing_slots": missing,
            })
            for slot in missing:
                missing_hist[slot] += 1
        else:
            digest, short = jarm_hash(parts, args.slots)
            complete.append({
                "ip_them": ip,
                "port_them": port,
                "jarm": short,
                "jarm_sha256": digest,
                "slots": args.slots,
                "parts": [parts[i] for i in range(1, args.slots + 1)],
            })
            jarm_counts[short] += 1

    stats = {
        "records": records,
        "invalid_records": invalid_records,
        "targets": len(groups),
        "complete": len(complete),
        "incomplete": len(retry),
        "duplicate_slots": duplicate_slots,
        "missing_slot_counts": {str(k): v for k, v in sorted(missing_hist.items())},
        "distinct_jarm": len(jarm_counts),
        "slots": args.slots,
    }

    def write_jsonl(path, rows):
        if not path:
            return
        with open(path, "w", encoding="utf-8") as out:
            for row in rows:
                out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    write_jsonl(args.complete_out, complete)
    write_jsonl(args.retry_out, retry)

    if args.retry_csv:
        with open(args.retry_csv, "w", encoding="utf-8", newline="") as out:
            out.write("ip_them,port_them,missing_slots\n")
            for row in retry:
                out.write("%s,%s,%s\n" % (
                    row["ip_them"], row["port_them"],
                    " ".join(str(s) for s in row["missing_slots"])))

    if args.retry_ip_file:
        with open(args.retry_ip_file, "w", encoding="utf-8") as out:
            for ip in sorted({row["ip_them"] for row in retry}):
                out.write(ip + "\n")

    if args.stats_out:
        with open(args.stats_out, "w", encoding="utf-8") as out:
            json.dump(stats, out, indent=2, sort_keys=True)
            out.write("\n")

    json.dump(stats, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
