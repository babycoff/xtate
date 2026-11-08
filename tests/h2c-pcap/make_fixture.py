#!/usr/bin/env python3
"""Synthetic cleartext HTTP/2 frames for offline h2c tests.

Multiple copies of the same frame sequence are used deliberately: the pcap
savefile reaches EOF immediately after its trailer and a single data packet can
race the handler dispatch under redirected CI output. All copies carry the same
ZBanner ACK number and distinct TCP sequence numbers.
"""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "pcap"))
import lib  # noqa: E402

FRAMES = (
    b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"          # SETTINGS
    b"\x00\x00\x01\x01\x04\x00\x00\x00\x01\x88"      # HEADERS :status 200
    b"\x00\x00\x05\x00\x01\x00\x00\x00\x01hello"     # DATA
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--copies", type=int, default=6)
    args = ap.parse_args()

    target, target_port = "172.20.0.4", 8446
    me, source_port = "172.20.0.5", 40000
    ck = lib.tcp_cookie(target, target_port, me, source_port, 123)
    server_seq = 1000
    packets = [
        (lib.tcp(target, target_port, me, source_port, server_seq, ck + 1,
                 lib.TCP_SYN | lib.TCP_ACK), 1.0)
    ]
    for i in range(args.copies):
        packets.append((lib.tcp(
            target, target_port, me, source_port,
            server_seq + 1 + i * len(FRAMES), ck + 50 + 1,
            lib.TCP_PSH | lib.TCP_ACK, FRAMES, i + 1), 1.01 + i * 0.01))
    packets.append((lib.tcp(target, target_port, me, source_port, server_seq, 0,
                            lib.TCP_SYN | lib.TCP_ACK, ident=99), 2.0))
    with lib.PcapWriter(args.out) as out:
        for packet, ts in packets:
            out.add(packet, ts)
    print(f"generated {args.out} frames={len(FRAMES)} copies={args.copies}")


if __name__ == "__main__":
    main()
