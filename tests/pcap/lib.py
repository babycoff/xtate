#!/usr/bin/env python3
"""Small deterministic packet/pcap toolkit for offline Xtate tests.

The helpers build Ethernet frames carrying IPv4/IPv6 TCP or UDP payloads and
write classic pcap files.  They deliberately do not capture or transmit: tests
feed the file through Xtate's receive-only ``file:`` adapter.
"""
import ipaddress
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "large-batch"))
from make_pcap import checksum, siphash24  # noqa: E402

ETH_SRC = b"\x02\x00\x00\x00\x00\x02"
ETH_DST = b"\x02\x00\x00\x00\x00\x01"

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


def tcp_cookie(ip_them, port_them, ip_me, port_me, seed):
    data = struct.pack("<IIII", int(ipaddress.IPv4Address(ip_them)),
                       port_them & 0xFFFF,
                       int(ipaddress.IPv4Address(ip_me)),
                       port_me & 0xFFFF)
    key = struct.pack("<QQ", seed, seed)
    return siphash24(data, key) & 0xFFFFFFFF


def tcp_cookie6(ip_them, port_them, ip_me, port_me, seed):
    hi, lo = struct.unpack(">QQ", ipaddress.IPv6Address(ip_them).packed)
    hi_me, lo_me = struct.unpack(">QQ", ipaddress.IPv6Address(ip_me).packed)
    data = struct.pack("<5Q", hi, lo, hi_me, lo_me,
                       ((port_them & 0xFFFF) << 16) | (port_me & 0xFFFF))
    key = struct.pack("<QQ", seed, seed)
    return siphash24(data, key) & 0xFFFFFFFF


def _tcp_header(port_them, port_me, seqno, ackno, flags, payload, window):
    return struct.pack("!HHIIBBHHH", port_them, port_me, seqno & 0xFFFFFFFF,
                       ackno & 0xFFFFFFFF, 0x50, flags, window, 0, 0) + payload


def tcp4(ip_them, port_them, ip_me, port_me, seqno, ackno, flags,
         payload=b"", ident=0, window=65535):
    src = ipaddress.IPv4Address(ip_them).packed
    dst = ipaddress.IPv4Address(ip_me).packed
    tcp = _tcp_header(port_them, port_me, seqno, ackno, flags, payload, window)
    total_len = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF,
                     0, 64, 6, 0, src, dst)
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, 6, len(tcp))
    csum = checksum(pseudo + tcp)
    tcp = struct.pack("!HHIIBBHHH", port_them, port_me, seqno & 0xFFFFFFFF,
                      ackno & 0xFFFFFFFF, 0x50, flags, window, csum, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF,
                     0, 64, 6, checksum(ip), src, dst)
    return struct.pack("!6s6sH", ETH_SRC, ETH_DST, 0x0800) + ip + tcp


def tcp6(ip_them, port_them, ip_me, port_me, seqno, ackno, flags,
         payload=b"", ident=0, window=65535):
    del ident
    src = ipaddress.IPv6Address(ip_them).packed
    dst = ipaddress.IPv6Address(ip_me).packed
    tcp = _tcp_header(port_them, port_me, seqno, ackno, flags, payload, window)
    upper_len = len(tcp)
    pseudo = src + dst + struct.pack("!I", upper_len) + b"\x00\x00\x00\x06"
    csum = checksum(pseudo + tcp)
    tcp = struct.pack("!HHIIBBHHH", port_them, port_me, seqno & 0xFFFFFFFF,
                      ackno & 0xFFFFFFFF, 0x50, flags, window, csum, 0) + payload
    ip6 = struct.pack("!IHBB16s16s", 0x60000000, upper_len, 6, 64, src, dst)
    return struct.pack("!6s6sH", ETH_SRC, ETH_DST, 0x86DD) + ip6 + tcp


def tcp(ip_them, port_them, ip_me, port_me, seqno, ackno, flags,
        payload=b"", ident=0, window=65535, ip_version=4):
    if ip_version == 6:
        return tcp6(ip_them, port_them, ip_me, port_me, seqno, ackno, flags,
                    payload, ident, window)
    return tcp4(ip_them, port_them, ip_me, port_me, seqno, ackno, flags,
                payload, ident, window)


def icmp_port_unreachable4(ip_them, port_them, ip_me, port_me, ident=0):
    """ICMPv4 destination-unreachable/port-unreachable with embedded UDP."""
    src = ipaddress.IPv4Address(ip_them).packed
    dst = ipaddress.IPv4Address(ip_me).packed
    # The inner packet is the original outbound UDP packet: me -> them.
    inner_src = dst
    inner_dst = src
    inner_ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, ident & 0xFFFF,
                           0, 64, 17, 0, inner_src, inner_dst)
    inner_ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, ident & 0xFFFF,
                           0, 64, 17, checksum(inner_ip), inner_src,
                           inner_dst)
    inner_udp = struct.pack("!HHHH", port_me, port_them, 8, 0)
    icmp = struct.pack("!BBHI", 3, 3, 0, 0) + inner_ip + inner_udp
    icmp = struct.pack("!BBHI", 3, 3, 0, checksum(icmp)) + inner_ip + inner_udp
    total_len = 20 + len(icmp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF,
                     0, 64, 1, 0, src, dst)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF,
                     0, 64, 1, checksum(ip), src, dst)
    return struct.pack("!6s6sH", ETH_SRC, ETH_DST, 0x0800) + ip + icmp


def icmp_port_unreachable6(ip_them, port_them, ip_me, port_me, ident=0):
    """ICMPv6 destination-unreachable/port-unreachable with embedded UDP."""
    del ident
    src = ipaddress.IPv6Address(ip_them).packed
    dst = ipaddress.IPv6Address(ip_me).packed
    inner_src = dst
    inner_dst = src
    inner_udp = struct.pack("!HHHH", port_me, port_them, 8, 0)
    inner_ip6 = struct.pack("!IHBB16s16s", 0x60000000, len(inner_udp), 17,
                            64, inner_src, inner_dst)
    icmp = struct.pack("!BBHI", 1, 4, 0, 0) + inner_ip6 + inner_udp
    pseudo = src + dst + struct.pack("!I", len(icmp)) + b"\x00\x00\x00\x3a"
    icmp = struct.pack("!BBHI", 1, 4, checksum(pseudo + icmp), 0) + \
        inner_ip6 + inner_udp
    ip6 = struct.pack("!IHBB16s16s", 0x60000000, len(icmp), 58, 64, src, dst)
    return struct.pack("!6s6sH", ETH_SRC, ETH_DST, 0x86DD) + ip6 + icmp


def udp4(ip_them, port_them, ip_me, port_me, payload=b"", ident=0):
    src = ipaddress.IPv4Address(ip_them).packed
    dst = ipaddress.IPv4Address(ip_me).packed
    udp = struct.pack("!HHHH", port_them, port_me, 8 + len(payload), 0) + payload
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, 17, len(udp))
    udp = struct.pack("!HHHH", port_them, port_me, 8 + len(payload),
                      checksum(pseudo + udp)) + payload
    total_len = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF,
                     0, 64, 17, 0, src, dst)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident & 0xFFFF,
                     0, 64, 17, checksum(ip), src, dst)
    return struct.pack("!6s6sH", ETH_SRC, ETH_DST, 0x0800) + ip + udp


def udp6(ip_them, port_them, ip_me, port_me, payload=b"", ident=0):
    del ident
    src = ipaddress.IPv6Address(ip_them).packed
    dst = ipaddress.IPv6Address(ip_me).packed
    udp = struct.pack("!HHHH", port_them, port_me, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack("!I", len(udp)) + b"\x00\x00\x00\x11"
    udp = struct.pack("!HHHH", port_them, port_me, 8 + len(payload),
                      checksum(pseudo + udp)) + payload
    ip6 = struct.pack("!IHBB16s16s", 0x60000000, len(udp), 17, 64, src, dst)
    return struct.pack("!6s6sH", ETH_SRC, ETH_DST, 0x86DD) + ip6 + udp


def udp(ip_them, port_them, ip_me, port_me, payload=b"", ident=0,
        ip_version=4):
    if ip_version == 6:
        return udp6(ip_them, port_them, ip_me, port_me, payload, ident)
    return udp4(ip_them, port_them, ip_me, port_me, payload, ident)


class PcapWriter:
    """Write classic little-endian Ethernet pcap files."""

    def __init__(self, path):
        self.path = pathlib.Path(path)
        self._fh = None

    def __enter__(self):
        self._fh = self.path.open("wb")
        self._fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                   65535, 1))
        self._t = 0.0
        return self

    def add(self, packet, ts=None):
        if ts is None:
            ts = self._t
        self._t = ts
        self._fh.write(struct.pack("<IIII", int(ts),
                                   int((ts % 1) * 1000000),
                                   len(packet), len(packet)))
        self._fh.write(packet)

    def add_trailer(self, packet, ts=None):
        self.add(packet, ts)

    def __exit__(self, exc_type, exc, tb):
        self._fh.close()
        self._fh = None

    def close(self):
        self.__exit__(None, None, None)


def replay_args(pcap, source_ip, source_mac="02-00-00-00-00-01",
                router_mac="02-00-00-00-00-02"):
    return [
        "--adapter", f"file:{pcap}",
        "--source-ip", source_ip,
        "--source-mac", source_mac,
        "--router-mac", router_mac,
    ]
