#!/usr/bin/env python3
"""Generate a deterministic pcap of valid tcp-syn responses for offline tests.

The packets are delivered to the scanner as if they came from the listed target
addresses. This is a test fixture generator only; no packets are sent.
"""
import argparse
import ipaddress
import struct


def sipround(v0, v1, v2, v3):
    v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
    v1 = ((v1 << 13) | (v1 >> 51)) & 0xFFFFFFFFFFFFFFFF
    v1 ^= v0
    v0 = ((v0 << 32) | (v0 >> 32)) & 0xFFFFFFFFFFFFFFFF
    v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
    v3 = ((v3 << 16) | (v3 >> 48)) & 0xFFFFFFFFFFFFFFFF
    v3 ^= v2
    v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
    v3 = ((v3 << 21) | (v3 >> 43)) & 0xFFFFFFFFFFFFFFFF
    v3 ^= v0
    v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
    v1 = ((v1 << 17) | (v1 >> 47)) & 0xFFFFFFFFFFFFFFFF
    v1 ^= v2
    v2 = ((v2 << 32) | (v2 >> 32)) & 0xFFFFFFFFFFFFFFFF
    return v0, v1, v2, v3


def siphash24(data, key):
    v0 = 0x736F6D6570736575
    v1 = 0x646F72616E646F6D
    v2 = 0x6C7967656E657261
    v3 = 0x7465646279746573
    k0, k1 = struct.unpack("<QQ", key)
    v3 ^= k1
    v2 ^= k0
    v1 ^= k1
    v0 ^= k0
    end = len(data) - (len(data) % 8)
    b = (len(data) & 0xFF) << 56
    for off in range(0, end, 8):
        m = struct.unpack_from("<Q", data, off)[0]
        v3 ^= m
        for _ in range(2):
            v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0 ^= m
    tail = data[end:]
    for i, x in enumerate(tail):
        b |= x << (8 * i)
    v3 ^= b
    for _ in range(2):
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0 ^= b
    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & 0xFFFFFFFFFFFFFFFF


def cookie(ip_them, port_them, ip_me, port_me, entropy):
    data = struct.pack("<IIII", ip_them, port_them, ip_me, port_me)
    key = struct.pack("<QQ", entropy, entropy)
    return siphash24(data, key) & 0xFFFFFFFF


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_packet(ip_them, port_them, ip_me, source_port, ackno, ident, seqno):
    # Ethernet
    eth = struct.pack("!6s6sH", b"\x02\x00\x00\x00\x00\x02",
                      b"\x02\x00\x00\x00\x00\x01", 0x0800)
    # IPv4
    src = ipaddress.IPv4Address(ip_them).packed
    dst = ipaddress.IPv4Address(ip_me).packed
    total_len = 20 + 20
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF, 0,
                     64, 6, 0, src, dst)
    ip_csum = checksum(ip)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF, 0,
                     64, 6, ip_csum, src, dst)
    # TCP SYN|ACK: ackno is cookie + 1
    tcp = struct.pack("!HHIIBBHHH", port_them, source_port, seqno & 0xFFFFFFFF,
                      ackno & 0xFFFFFFFF, 0x50, 0x12, 65535, 0, 0)
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, 6, len(tcp))
    tcp_csum = checksum(pseudo + tcp)
    tcp = struct.pack("!HHIIBBHHH", port_them, source_port, seqno & 0xFFFFFFFF,
                      ackno & 0xFFFFFFFF, 0x50, 0x12, 65535, tcp_csum, 0)
    return eth + ip + tcp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--targets", required=True)
    ap.add_argument("--ports", required=True,
                    help="inclusive port range, e.g. 1-1000")
    ap.add_argument("--ip-me", default="192.0.2.1")
    ap.add_argument("--source-port", type=int, default=40000)
    ap.add_argument("--seed", type=int, default=123)
    ap.add_argument("--pps", type=int, default=20000,
                    help="timestamp spacing for replay pacing")
    ap.add_argument("--trailer", type=int, default=100,
                    help="invalid tail packets to avoid dropping the last valid reply")
    args = ap.parse_args()

    with open(args.targets, encoding="utf-8") as fh:
        targets = [line.strip() for line in fh if line.strip()]
    lo, hi = (int(x) for x in args.ports.split("-", 1))
    ip_me = int(ipaddress.IPv4Address(args.ip_me))

    # pcap global header: little-endian, Ethernet
    with open(args.out, "wb") as out:
        out.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        count = 0
        for ip in targets:
            ip_them = int(ipaddress.IPv4Address(ip))
            for port in range(lo, hi + 1):
                ack = cookie(ip_them, port, ip_me, args.source_port,
                             args.seed) + 1
                pkt = make_packet(ip, port, args.ip_me, args.source_port,
                                  ack, count, 1000 + count)
                ts_us = (count * 1000000) // args.pps
                ts = ts_us // 1000000
                usec = ts_us % 1000000
                out.write(struct.pack("<IIII", ts, usec, len(pkt), len(pkt)))
                out.write(pkt)
                count += 1
        # A savefile reaches EOF immediately after the last record. Add a small
        # invalid trailer so the receive-side finish path cannot race the final
        # valid reply.
        for j in range(args.trailer):
            port = lo
            ack = cookie(int(ipaddress.IPv4Address(targets[0])), port, ip_me,
                         args.source_port, args.seed) + 2
            pkt = make_packet(targets[0], port, args.ip_me, args.source_port,
                              ack, count, 2000 + count)
            ts_us = (count * 1000000) // args.pps
            out.write(struct.pack("<IIII", ts_us // 1000000,
                                  ts_us % 1000000, len(pkt), len(pkt)))
            out.write(pkt)
            count += 1
    print("generated", count, "packets")


if __name__ == "__main__":
    main()
