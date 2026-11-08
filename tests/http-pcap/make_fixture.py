#!/usr/bin/env python3
"""Build an offline ZBanner+HTTP response fixture for match tests."""
import argparse
import pathlib
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
    ap.add_argument("--payload-len", type=int, default=47,
                    help="actual HTTP request length for -probe-arg "
                         "--user-agent=a")
    ap.add_argument("--response", default=(
        "HTTP/1.1 200 OK\r\n"
        "Server: xtate-test\r\n"
        "Content-Length: 11\r\n"
        "\r\n"
        "hello world"))
    args = ap.parse_args()

    ck = lib.tcp_cookie(args.target, args.target_port, args.ip_me,
                        args.source_port, args.seed)
    server_seq = 1000

    def pkt(seq, ack, flags, payload=b"", ident=0):
        return lib.tcp(args.target, args.target_port, args.ip_me,
                       args.source_port, seq, ack, flags, payload, ident)

    packets = [
        (pkt(server_seq, ck + 1, lib.TCP_SYN | lib.TCP_ACK), 1.0),
        (pkt(server_seq + 1, ck + args.payload_len + 1,
             lib.TCP_PSH | lib.TCP_ACK, args.response.encode(), 1), 1.01),
        (pkt(server_seq, 0, lib.TCP_SYN | lib.TCP_ACK, ident=1000), 1.2),
    ]
    with lib.PcapWriter(args.out) as out:
        for packet, ts in packets:
            out.add(packet, ts)
    print(f"generated {args.out} response={len(args.response)} bytes")


if __name__ == "__main__":
    main()
