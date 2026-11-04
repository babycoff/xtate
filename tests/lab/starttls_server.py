#!/usr/bin/env python3
"""Minimal SMTP/IMAP/POP3/FTP STARTTLS targets for the local lab."""
import socket
import ssl
import sys
import threading

CERT = sys.argv[1]
KEY = sys.argv[2]

SPECS = {
    "smtp": (2525, b"220 lab ESMTP\r\n"),
    "imap": (2143, b"* OK lab IMAP ready\r\n"),
    "pop3": (2110, b"+OK lab POP3 ready\r\n"),
    "ftp":  (2121, b"220 lab FTP ready\r\n"),
}


def read_line(conn, buf):
    while b"\n" not in buf:
        data = conn.recv(4096)
        if not data:
            return None, buf
        buf += data
    line, buf = buf.split(b"\n", 1)
    return line.rstrip(b"\r\n"), buf


def serve(proto, port, greeting):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    while True:
        conn, _ = srv.accept()
        try:
            conn.sendall(greeting)
            buf = b""
            if proto == "smtp":
                line, buf = read_line(conn, buf)
                conn.sendall(b"250-lab\r\n250 STARTTLS\r\n")
                line, buf = read_line(conn, buf)
                if not line or b"STARTTLS" not in line.upper():
                    conn.close()
                    continue
                conn.sendall(b"220 Ready to start TLS\r\n")
            elif proto == "imap":
                line, buf = read_line(conn, buf)
                conn.sendall(b"a001 OK Begin TLS\r\n")
            elif proto == "pop3":
                line, buf = read_line(conn, buf)
                conn.sendall(b"+OK Begin TLS\r\n")
            else:
                line, buf = read_line(conn, buf)
                conn.sendall(b"234 Proceed with negotiation\r\n")

            tls = ctx.wrap_socket(conn, server_side=True)
            tls.settimeout(3)
            tls.do_handshake()
            try:
                tls.recv(1)
            except Exception:
                pass
            tls.close()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass


threads = []
for proto, (port, greeting) in SPECS.items():
    t = threading.Thread(target=serve, args=(proto, port, greeting), daemon=True)
    t.start()
    threads.append(t)
for t in threads:
    t.join()
