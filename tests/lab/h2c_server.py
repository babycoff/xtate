#!/usr/bin/env python3
"""Minimal cleartext HTTP/2 server used by the H2C depth matrix."""
import socket

SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
HEADERS = b"\x00\x00\x01\x01\x04\x00\x00\x00\x01\x88"
DATA = b"\x00\x00\x05\x00\x01\x00\x00\x00\x01hello"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 8446))
s.listen()
while True:
    conn, _ = s.accept()
    try:
        conn.recv(4096)
        conn.sendall(SETTINGS + HEADERS + DATA)
        conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
