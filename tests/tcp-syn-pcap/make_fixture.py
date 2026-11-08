#!/usr/bin/env python3
"""tcp-syn offline fixture: SYN-ACK or RST with the scan cookie."""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "pcap"))
import lib  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", choices=["synack", "rst"], default="synack")
    ap.add_argument("--target", default="192.0.2.2")
    ap.add_argument("--target-port", type=int, default=8080)
    ap.add_argument("--ip-me", default="192.0.2.1")
    ap.add_argument("--source-port", type=int, default=40000)
    ap.add_argument("--seed", type=int, default=123)
    args = ap.parse_args()

    ck = lib.tcp_cookie(args.target, args.target_port, args.ip_me,
                        args.source_port, args.seed)
    if args.mode == "synack":
        flags = lib.TCP_SYN | lib.TCP_ACK
        ack = ck + 1
    else:
        flags = lib.TCP_RST | lib.TCP_ACK
        ack = ck
    packets = [
        lib.tcp(args.target, args.target_port, args.ip_me, args.source_port,
                1000, ack, flags),
        lib.tcp(args.target, args.target_port, args.ip_me, args.source_port,
                1000, 0, lib.TCP_SYN | lib.TCP_ACK),
    ]
    with lib.PcapWriter(args.out) as out:
        for i, packet in enumerate(packets):
            out.add(packet, 1.0 + i * 0.1)
    print(f"generated {args.out} mode={args.mode}")


if __name__ == "__main__":
    main()
