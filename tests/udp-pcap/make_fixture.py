#!/usr/bin/env python3
"""UDP echo-response pcap fixture with the scan cookie bytes."""
import argparse
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "pcap"))
import lib  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--target", default="192.0.2.2")
    ap.add_argument("--target-port", type=int, default=8080)
    ap.add_argument("--ip-me", default="192.0.2.1")
    ap.add_argument("--source-port", type=int, default=40000)
    ap.add_argument("--seed", type=int, default=123)
    args = ap.parse_args()

    ck = lib.tcp_cookie(args.target, args.target_port, args.ip_me,
                        args.source_port, args.seed)
    good = struct.pack(">I", ck)
    packets = [
        lib.udp(args.target, args.target_port, args.ip_me, args.source_port,
                good),
        lib.udp(args.target, args.target_port, args.ip_me, args.source_port,
                b"bad"),
    ]
    with lib.PcapWriter(args.out) as out:
        for i, packet in enumerate(packets):
            out.add(packet, 1.0 + i * 0.1)
    print(f"generated {args.out} cookie={ck}")


if __name__ == "__main__":
    main()
