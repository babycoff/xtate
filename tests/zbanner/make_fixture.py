#!/usr/bin/env python3
"""Generate deterministic pcap fixtures for ZBanner offline tests.

Fixtures are fed through Xtate's receive-only ``file:`` adapter.  Every file
ends with an intentionally invalid trailer: a pcap savefile reaches EOF
immediately after the last useful record and the receive path can otherwise
finish before the last valid reply is dispatched.
"""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "pcap"))
import lib  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", required=True,
                    choices=["synack", "rst", "banner", "wrong-ack"])
    ap.add_argument("--target", default="192.0.2.2")
    ap.add_argument("--target-port", type=int, default=8080)
    ap.add_argument("--ip-me", default="192.0.2.1")
    ap.add_argument("--ip-version", type=int, choices=[4, 6], default=4)
    ap.add_argument("--window", type=int, default=65535)
    ap.add_argument("--source-port", type=int, default=40000)
    ap.add_argument("--seed", type=int, default=123)
    ap.add_argument("--payload-len", type=int, default=47,
                    help="actual probe payload length; for HTTP with "
                         "--user-agent=a this is 47")
    ap.add_argument("--segments", type=int, default=1)
    ap.add_argument("--banner-size", type=int, default=32)
    ap.add_argument("--retransmit", action="store_true")
    args = ap.parse_args()

    if args.ip_version == 6:
        ck = lib.tcp_cookie6(args.target, args.target_port, args.ip_me,
                             args.source_port, args.seed)
    else:
        ck = lib.tcp_cookie(args.target, args.target_port, args.ip_me,
                            args.source_port, args.seed)
    server_seq = 1000
    packets = []
    t = 1.0

    def pkt(seqno, ackno, flags, payload=b"", ident=0):
        return lib.tcp(args.target, args.target_port, args.ip_me,
                       args.source_port, seqno, ackno, flags, payload, ident,
                       args.window, args.ip_version)

    if args.mode == "rst":
        packets.append((pkt(server_seq, ck, lib.TCP_RST | lib.TCP_ACK), t))
    else:
        packets.append((pkt(server_seq, ck + 1, lib.TCP_SYN | lib.TCP_ACK), t))
        if args.mode in ("banner", "wrong-ack"):
            data_ack = ck + args.payload_len + 1
            if args.mode == "wrong-ack":
                data_ack += 1
            payload = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"
                       b"ok" + b"X" * max(0, args.banner_size - 42))
            for i in range(args.segments):
                packets.append((pkt(server_seq + 1 + i * len(payload),
                                    data_ack, lib.TCP_PSH | lib.TCP_ACK,
                                    payload, i + 1), t + 0.01 * (i + 1)))
            if args.retransmit and args.segments:
                packets.append((pkt(server_seq + 1, data_ack,
                                    lib.TCP_PSH | lib.TCP_ACK, payload, 99),
                                t + 0.03))

    # Invalid trailer: see module docstring.
    packets.append((pkt(server_seq, 0, lib.TCP_SYN | lib.TCP_ACK, ident=1000),
                    t + 0.2))

    out_path = pathlib.Path(args.out)
    with lib.PcapWriter(out_path) as out:
        for packet, ts in packets:
            out.add(packet, ts)
    print(f"generated {out_path} mode={args.mode} packets={len(packets)}")


if __name__ == "__main__":
    main()
