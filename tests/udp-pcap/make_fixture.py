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
    ap.add_argument("--mode", choices=["echo", "icmp"], default="echo")
    ap.add_argument("--ip-version", type=int, choices=[4, 6], default=4)
    ap.add_argument("--target", default="192.0.2.2")
    ap.add_argument("--target-port", type=int, default=8080)
    ap.add_argument("--ip-me", default="192.0.2.1")
    ap.add_argument("--source-port", type=int, default=40000)
    ap.add_argument("--seed", type=int, default=123)
    args = ap.parse_args()

    if args.ip_version == 6:
        ck = lib.tcp_cookie6(args.target, args.target_port, args.ip_me,
                             args.source_port, args.seed)
    else:
        ck = lib.tcp_cookie(args.target, args.target_port, args.ip_me,
                            args.source_port, args.seed)
    good = struct.pack(">I", ck)
    if args.mode == "icmp":
        builder = (lib.icmp_port_unreachable6 if args.ip_version == 6
                   else lib.icmp_port_unreachable4)
        packets = [
            builder(args.target, args.target_port, args.ip_me,
                    args.source_port),
            builder(args.target, args.target_port, args.ip_me,
                    args.source_port + 1),
        ]
    else:
        packets = [
            lib.udp(args.target, args.target_port, args.ip_me,
                    args.source_port, good, ip_version=args.ip_version),
            lib.udp(args.target, args.target_port, args.ip_me,
                    args.source_port, b"bad", ip_version=args.ip_version),
        ]
    with lib.PcapWriter(args.out) as out:
        for i, packet in enumerate(packets):
            out.add(packet, 1.0 + i * 0.1)
    print(f"generated {args.out} cookie={ck}")


if __name__ == "__main__":
    main()
