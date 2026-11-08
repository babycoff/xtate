#!/usr/bin/env python3
"""Deterministic fake servers for IPP, AMQP and PPTP probes."""
import socket
import struct
import threading


def serve(port, handler):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen()
    while True:
        c, _ = s.accept()
        threading.Thread(target=handler, args=(c,), daemon=True).start()


def ipp(c):
    c.recv(65536)
    ipp = b"\x01\x01\x00\x00\x00\x00\x00\x01"
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\n"
              b"Content-Length: 8\r\nConnection: close\r\n\r\n" + ipp)
    c.close()


def amqp(c):
    c.recv(64)
    payload = struct.pack(">HHBBII", 10, 10, 0, 9, 0, 0)
    frame = b"\x01" + struct.pack(">H", 0) + struct.pack(">I", len(payload)) + payload
    c.sendall(frame)
    c.close()


def pptp(c):
    c.recv(1024)
    r = bytearray(156)
    r[0:2] = struct.pack(">H", 156)
    r[2:4] = struct.pack(">H", 2)
    r[4:8] = b"\x1a\x2b\x3c\x4d"
    r[8:10] = struct.pack(">H", 2)
    r[12:14] = struct.pack(">H", 0x0100)
    r[14] = 1  # result code: general error
    r[15] = 0
    r[16:20] = struct.pack(">I", 1)
    r[20:24] = struct.pack(">I", 1)
    r[28:33] = b"xtate"
    r[92:97] = b"xtate"
    c.sendall(r)
    c.close()


for port, handler in [(631, ipp), (5672, amqp), (1723, pptp)]:
    threading.Thread(target=serve, args=(port, handler), daemon=True).start()

threading.Event().wait()
