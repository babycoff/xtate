#!/usr/bin/env python3
"""Generate deterministic pcap fixtures for ZBanner offline tests.

The scanner is normally a raw-socket transmitter.  These fixtures are fed back
through the receive-only ``file:`` adapter, so no network or root privileges are
needed.  Every fixture ends with an intentionally invalid trailer: a pcap
savefile reaches EOF immediately after the last useful record and the receive
path can otherwise finish before the last valid reply is dispatched.
"""
import argparse
import ipaddress
import pathlib
import struct
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "large-batch"))
from make_pcap import cookie, checksum  # noqa: E402

ETH_SRC = b"\x02\x00\x00\x00\x00\x02"
ETH_DST = b"\x02\x00\x00\x00\x00\x01"


def tcp_packet(ip_them, port_them, ip_me, port_me, seqno, ackno, flags,
               payload=b"", ident=0):
    src = ipaddress.IPv4Address(ip_them).packed
    dst = ipaddress.IPv4Address(ip_me).packed
    total_len = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF,
                     0, 64, 6, 0, src, dst)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF,
                     0, 64, 6, checksum(ip), src, dst)
    tcp = struct.pack("!HHIIBBHHH", port_them, port_me, seqno & 0xFFFFFFFF,
                      ackno & 0xFFFFFFFF, 0x50, flags, 65535, 0, 0)
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, 6, len(tcp) + len(payload))
    csum = checksum(pseudo + tcp + payload)
    tcp = struct.pack("!HHIIBBHHH", port_them, port_me, seqno & 0xFFFFFFFF,
                      ackno & 0xFFFFFFFF, 0x50, flags, 65535, csum, 0)
    eth = struct.pack("!6s6sH", ETH_SRC, ETH_DST, 0x0800)
    return eth + ip + tcp + payload


def add_record(out, pkt, seconds):
    out.write(struct.pack("<IIII", int(seconds), int((seconds % 1) * 1000000),
                          len(pkt), len(pkt)))
    out.write(pkt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", required=True,
                    choices=["synack", "rst", "banner", "wrong-ack"])
    ap.add_argument("--target", default="192.0.2.2")
    ap.add_argument("--target-port", type=int, default=8080)
    ap.add_argument("--ip-me", default="192.0.2.1")
    ap.add_argument("--source-port", type=int, default=40000)
    ap.add_argument("--seed", type=int, default=123)
    ap.add_argument("--payload-len", type=int, default=47,
                    help="actual probe payload length; for HTTP with "
                         "--user-agent=a this is 47")
    ap.add_argument("--segments", type=int, default=1)
    ap.add_argument("--banner-size", type=int, default=32)
    ap.add_argument("--retransmit", action="store_true")
    args = ap.parse_args()

    ip_me = int(ipaddress.IPv4Address(args.ip_me))
    ip_them = int(ipaddress.IPv4Address(args.target))
    ck = cookie(ip_them, args.target_port, ip_me, args.source_port,
                args.seed)
    server_seq = 1000
    ack = ck + 1
    packets = []
    t = 1.0

    if args.mode == "rst":
        packets.append((tcp_packet(args.target, args.target_port, args.ip_me,
                                   args.source_port, server_seq, ck,
                                   0x14), t))
    else:
        packets.append((tcp_packet(args.target, args.target_port, args.ip_me,
                                   args.source_port, server_seq, ack,
                                   0x12), t))
        if args.mode in ("banner", "wrong-ack"):
            data_ack = ck + args.payload_len + 1
            if args.mode == "wrong-ack":
                data_ack += 1
            payload = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"
                       b"ok" + b"X" * max(0, args.banner_size - 42))
            for i in range(args.segments):
                packets.append((tcp_packet(
                    args.target, args.target_port, args.ip_me,
                    args.source_port, server_seq + 1 + i * len(payload),
                    data_ack, 0x18, payload, ident=i + 1), t + 0.01 * (i + 1)))
            if args.retransmit and args.segments:
                packets.append((tcp_packet(
                    args.target, args.target_port, args.ip_me,
                    args.source_port, server_seq + 1, data_ack, 0x18,
                    payload, ident=99), t + 0.03))

    # A deliberately invalid trailer gives the receive thread one more event
    # after the last useful record.
    packets.append((tcp_packet(args.target, args.target_port, args.ip_me,
                               args.source_port, server_seq, 0, 0x12,
                               ident=1000), t + 0.2))

    out_path = pathlib.Path(args.out)
    with out_path.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for pkt, ts in packets:
            add_record(out, pkt, ts)
    print(f"generated {out_path} mode={args.mode} packets={len(packets)}")


if __name__ == "__main__":
    main()
