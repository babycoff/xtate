#!/usr/bin/env python3
"""Aggregate JARM parts emitted by Xtate's stateless `jarm` probe.

The scanner deliberately keeps no per-target group state.  Each of the ten
probe slots emits one OutItem with:

    probe report.jarm_slot  1..10
    probe report.jarm_slots 10
    probe report.jarm_part  "cipher|version|extensions"

This tool groups those rows by (ip_them, port_them), reports completeness,
computes the standard 62-character JARM 1.0 fuzzy hash from all ten parts, and writes a retry list for
targets that are missing slots.

This is an output-side post-processor: it is not part of the scanner hot path.
"""
import argparse
import hashlib
import json
import os
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


# Salesforce JARM's ordered cipher table.  The fuzzy hash records the index in
# this table, not a SHA-256 digest of the cipher name.  Keep this order exactly
# in sync with jarm.py (JARM 1.0).
JARM_CIPHERS = [
    "0004", "0005", "0007", "000a", "0016", "002f", "0033", "0035", "0039",
    "003c", "003d", "0041", "0045", "0067", "006b", "0084", "0088", "009a",
    "009c", "009d", "009e", "009f", "00ba", "00be", "00c0", "00c4", "c007",
    "c008", "c009", "c00a", "c011", "c012", "c013", "c014", "c023", "c024",
    "c027", "c028", "c02b", "c02c", "c02f", "c030", "c060", "c061", "c072",
    "c073", "c076", "c077", "c09c", "c09d", "c09e", "c09f", "c0a0", "c0a1",
    "c0a2", "c0a3", "c0ac", "c0ad", "c0ae", "c0af", "cc13", "cc14", "cca8",
    "cca9", "1301", "1302", "1303", "1304", "1305",
]


def cipher_bytes(cipher):
    """Return JARM's two-hex-character cipher index."""
    if not cipher:
        return "00"
    try:
        index = JARM_CIPHERS.index(cipher.lower()) + 1
    except ValueError:
        # An unknown cipher is not part of a valid JARM response; use the
        # conventional zero contribution rather than inventing an index.
        return "00"
    return f"{index:02x}"


def version_byte(version):
    """Return JARM's one-character TLS-version nibble (a-f)."""
    if not version or len(version) < 4:
        return "0"
    digit = int(version[3:4], 16)
    return "abcdef"[digit] if digit < 6 else "0"


def jarm_part_fields(part):
    fields = part.split("|", 3)
    while len(fields) < 4:
        fields.append("")
    return fields[0], fields[1], fields[2], fields[3]


def jarm_hash(parts, slots):
    """Build the standard 62-character JARM fingerprint.

    This follows Salesforce JARM's ``jarm_hash``: each of the ten slots
    contributes two hex characters for the selected cipher's index in the
    ordered cipher table and one character for the TLS-version nibble.  The
    remaining 32 characters are the first 32 hex characters of SHA-256 over
    the concatenated ALPN and extension strings.

    ``parts`` may be incomplete; missing slots use the conventional ``|||``
    and contribute ``000`` to the fuzzy prefix.
    """
    raw_parts = "".join(parts.get(i, "|||") for i in range(1, slots + 1))
    if ",".join(parts.get(i, "|||") for i in range(1, slots + 1)) == ",".join(
        "|||" for _ in range(slots)
    ):
        # Salesforce JARM's explicit all-refused case.
        digest = hashlib.sha256(raw_parts.encode("utf-8")).hexdigest()
        return digest, "0" * 62

    fuzzy = []
    alpns_ext = []
    for slot in range(1, slots + 1):
        part = parts.get(slot, "|||")
        cipher, version, alpn, ext = jarm_part_fields(part)
        fuzzy.append(cipher_bytes(cipher))
        fuzzy.append(version_byte(version))
        alpns_ext.append(alpn)
        alpns_ext.append(ext)
    first = "".join(fuzzy)
    second = hashlib.sha256("".join(alpns_ext).encode("utf-8")).hexdigest()[:32]
    digest = hashlib.sha256(raw_parts.encode("utf-8")).hexdigest()
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
    parser.add_argument("--retry-ports-file", metavar="FILE",
                        help="write the unique incomplete ports as a comma list")
    parser.add_argument("--retry-dir", metavar="DIR",
                        help="write one Xtate-readable IP list per incomplete port")
    parser.add_argument("--retry-template", default=None,
                        help="optional command template; placeholders: {ips_file}, {port}")
    parser.add_argument("--retry-extra", default="",
                        help="extra arguments appended to generated retry commands")
    parser.add_argument("--stats-out", metavar="FILE",
                        help="write aggregate statistics as JSON")
    args = parser.parse_args(argv)

    if args.slots < 1:
        parser.error("--slots must be positive")

    groups = defaultdict(dict)
    duplicate_slots = 0
    invalid_records = 0
    records_total = 0
    records_without_parts = 0

    for record in read_records(args.inputs):
        records_total += 1
        if record is None:
            invalid_records += 1
            continue
        ip, port = target_of(record)
        if ip is None or port is None:
            invalid_records += 1
            continue
        slot, part = part_of(record)
        if part is None:
            # A valid output row without a JARM part, e.g. an open row or a
            # non-TLS response. It cannot identify a JARM target on its own.
            records_without_parts += 1
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
        "records_total": records_total,
        "records_without_parts": records_without_parts,
        "invalid_records": invalid_records,
        "targets_with_parts": len(groups),
        "complete": len(complete),
        "incomplete": len(retry),
        "duplicate_slots": duplicate_slots,
        "missing_slot_counts": {str(k): v for k, v in sorted(missing_hist.items())},
        "distinct_jarm": len(jarm_counts),
        "slots": args.slots,
        "meaning": (
            "targets_with_parts counts only targets with at least one JARM part; "
            "it is not the number of scanned targets. A target whose first "
            "response was lost has no JARM row and is absent from these counts. "
            "complete and incomplete are subsets of targets_with_parts. "
            "records_without_parts counts valid rows (for example open rows) "
            "that carry no JARM part and therefore do not identify a JARM target."
        ),
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

    if args.retry_ports_file:
        with open(args.retry_ports_file, "w", encoding="utf-8") as out:
            out.write(",".join(str(port) for port in
                               sorted({row["port_them"] for row in retry})) + "\n")

    if args.retry_dir:
        os.makedirs(args.retry_dir, exist_ok=True)
        by_port = {}
        for row in retry:
            by_port.setdefault(row["port_them"], set()).add(row["ip_them"])
        commands = []
        for port in sorted(by_port):
            ips_file = os.path.join(args.retry_dir, f"port-{port}.ips")
            with open(ips_file, "w", encoding="utf-8") as out:
                for ip in sorted(by_port[port]):
                    out.write(ip + "\n")
            if args.retry_template:
                command = args.retry_template.format(ips_file=ips_file, port=port)
                if args.retry_extra:
                    command += " " + args.retry_extra
                commands.append(command)
        if commands:
            with open(os.path.join(args.retry_dir, "retry-commands.txt"),
                      "w", encoding="utf-8") as out:
                out.write("\n".join(commands) + "\n")

    if args.stats_out:
        with open(args.stats_out, "w", encoding="utf-8") as out:
            json.dump(stats, out, indent=2, sort_keys=True)
            out.write("\n")

    json.dump(stats, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
