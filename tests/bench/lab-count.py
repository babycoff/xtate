#!/usr/bin/env python3
"""Count TCP packets destined to a port range with a raw packet socket.

Used by the local Tx benchmark so the scan result is verified from the target
side rather than trusting only the scanner's own rate counter.
"""
import os
import socket
import struct
import sys


def main(start, end, count_path):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    count = 0
    with open(count_path, "w", encoding="ascii") as out:
        out.write("0\n")
        out.flush()
        while True:
            frame = sock.recv(65535)
            if len(frame) < 34:
                continue
            if frame[12:14] != b"\x08\x00":
                continue
            ip = frame[14:]
            if len(ip) < 20 or (ip[0] >> 4) != 4:
                continue
            ihl = (ip[0] & 0x0F) * 4
            if len(ip) < ihl + 20 or ip[9] != 6:
                continue
            tcp = ip[ihl:]
            dport = struct.unpack("!H", tcp[2:4])[0]
            flags = tcp[13]
            # Count only incoming SYN packets (not SYN-ACK or responses whose
            # destination port happens to fall in the same range).
            if start <= dport <= end and (flags & 0x02) and not (flags & 0x10):
                count += 1
                out.seek(0)
                out.write(f"{count}\n")
                out.truncate()
                out.flush()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: lab-count.py START_PORT END_PORT COUNT_PATH", file=sys.stderr)
        raise SystemExit(2)
    main(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3])
