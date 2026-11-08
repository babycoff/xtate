#!/usr/bin/env python3
"""Deterministic fake servers for the Batch B protocol probes."""
import socket
import struct
import threading
import time


def serve(port, handler):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen()
    while True:
        c, _ = s.accept()
        threading.Thread(target=handler, args=(c,), daemon=True).start()


def mysql(c):
    version = b"8.0.34"
    payload = (b"\x0a" + version + b"\x00" + struct.pack("<I", 42) +
               b"abcdefgh" + b"\x00" + struct.pack("<H", 0xffff) + b"\x21" +
               struct.pack("<H", 2) + struct.pack("<H", 0xffff) + b"\x15" +
               b"\x00" * 10 + b"mysql_native_password\x00")
    c.sendall(struct.pack("<I", len(payload))[:3] + b"\x00" + payload)
    c.close()


def postgres(c):
    try:
        req = c.recv(8)
        if len(req) == 8:
            c.sendall(b"N")
            c.recv(4096)
            c.sendall(b"R" + struct.pack(">I", 8) + struct.pack(">I", 5))
    finally:
        c.close()


def _bson_doc():
    def elem(t, key, val):
        return bytes([t]) + key.encode() + b"\x00" + val
    body = b""
    body += elem(0x01, "ok", struct.pack("<d", 1.0))
    body += elem(0x10, "maxWireVersion", struct.pack("<i", 17))
    v = b"7.0.0\x00"
    body += elem(0x02, "version", struct.pack("<i", len(v)) + v)
    body += elem(0x08, "isWritablePrimary", b"\x01")
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def mongodb(c):
    c.recv(65536)
    doc = _bson_doc()
    msg = struct.pack("<iiii", 16 + 4 + 1 + len(doc), 1, 0, 2013)
    msg += struct.pack("<i", 0) + b"\x00" + doc
    c.sendall(msg)
    c.close()


def smtp(c):
    c.sendall(b"220 test ESMTP\r\n")
    c.recv(4096)
    c.sendall(b"250-test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
    c.close()


def imap(c):
    c.sendall(b"* OK test IMAP\r\n")
    c.recv(4096)
    c.sendall(b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\na1 OK done\r\n")
    c.close()


def pop3(c):
    c.sendall(b"+OK test POP3\r\n")
    c.recv(4096)
    c.sendall(b"+OK\r\nUSER\r\nSTLS\r\n.\r\n")
    c.close()


def ftp(c):
    c.sendall(b"220 test FTP\r\n")
    c.recv(4096)
    c.sendall(b"211-Features:\r\n AUTH TLS\r\n211 End\r\n")
    c.close()


def sieve(c):
    c.sendall(b'"IMPLEMENTATION" "Example" "SIEVE" "fileinto" "STARTTLS" '
              b'"SASL" "PLAIN"\r\n')
    try:
        c.recv(4096)
    except Exception:
        pass
    c.close()


for port, handler in [
    (3307, mysql), (5432, postgres), (27018, mongodb), (2525, smtp),
    (1430, imap), (1100, pop3), (2121, ftp), (4190, sieve),
]:
    threading.Thread(target=serve, args=(port, handler), daemon=True).start()

threading.Event().wait()
