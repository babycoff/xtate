#!/usr/bin/env python3
import socket, ssl, struct, sys

cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
ctx.set_alpn_protocols(["dot"])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(16)

while True:
    raw, _ = s.accept()
    try:
        c = ctx.wrap_socket(raw, server_side=True)
        hdr = c.recv(2)
        if len(hdr) != 2:
            c.close(); continue
        n = struct.unpack("!H", hdr)[0]
        q = b""
        while len(q) < n:
            part = c.recv(n - len(q))
            if not part:
                break
            q += part
        if len(q) != n:
            c.close(); continue
        resp = bytearray(q)
        if len(resp) < 12:
            c.close(); continue
        resp[2] = 0x81
        resp[3] = 0x80
        resp[6:8] = b"\x00\x01"
        resp[8:10] = b"\x00\x00"
        resp[10:12] = b"\x00\x00"
        i = 12
        while i < len(resp) and resp[i] != 0:
            i += 1
        i += 5
        resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04"
        c.sendall(struct.pack("!H", len(resp)) + resp)
        c.close()
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
