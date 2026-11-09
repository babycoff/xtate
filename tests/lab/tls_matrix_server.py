#!/usr/bin/env python3
"""Implicit-TLS fake servers for the TLS composition matrix."""
import socket
import ssl
import struct
import sys
import threading

CERT, KEY = sys.argv[1], sys.argv[2]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
ctx.set_alpn_protocols(["h2"])


def bson_doc():
    def elem(t, key, val):
        return bytes([t]) + key.encode() + b"\x00" + val
    body = elem(0x01, "ok", struct.pack("<d", 1.0))
    body += elem(0x10, "maxWireVersion", struct.pack("<i", 17))
    v = b"7.0.0\x00"
    body += elem(0x02, "version", struct.pack("<i", len(v)) + v)
    body += elem(0x08, "isWritablePrimary", b"\x01")
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def mysql(c):
    version = b"8.0.34"
    payload = (b"\x0a" + version + b"\x00" + struct.pack("<I", 42) +
               b"abcdefgh" + b"\x00" + struct.pack("<H", 0xffff) + b"\x21" +
               struct.pack("<H", 2) + struct.pack("<H", 0xffff) + b"\x15" +
               b"\x00" * 10 + b"mysql_native_password\x00")
    c.sendall(struct.pack("<I", len(payload))[:3] + b"\x00" + payload)


def postgres(c):
    c.recv(4096)
    c.sendall(b"R" + struct.pack(">I", 8) + struct.pack(">I", 5))


def mongodb(c):
    c.recv(65536)
    doc = bson_doc()
    msg = struct.pack("<iiii", 16 + 4 + 1 + len(doc), 1, 0, 2013)
    msg += struct.pack("<i", 0) + b"\x00" + doc
    c.sendall(msg)


def smtp(c):
    # The implicit-SMTP case runs smtp-state --after-tls: wait for EHLO
    # and answer with capabilities, without a second greeting.
    if c.recv(4096):
        c.sendall(b"250-lab\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")


def serve(port, handler):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen()
    while True:
        conn, _ = s.accept()
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
            handler(tls)
            tls.close()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass


for port, handler in [(2465, smtp), (3307, mysql),
                      (5432, postgres), (27018, mongodb)]:
    threading.Thread(target=serve, args=(port, handler), daemon=True).start()

threading.Event().wait()
