#!/usr/bin/env python3
import ssl, socket, struct, sys, threading

cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
ctx.set_alpn_protocols(["http/1.1"])

def dns_response(q):
    if len(q) < 12:
        return b""
    r = bytearray(q)
    r[2] = 0x81; r[3] = 0x80
    r[6:8] = b"\x00\x01"; r[8:10] = b"\x00\x00"; r[10:12] = b"\x00\x00"
    i = 12
    while i < len(r) and r[i] != 0:
        i += 1
    i += 5
    r += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04"
    return bytes(r)

def handle(c):
    try:
        c = ctx.wrap_socket(c, server_side=True)
        data = b""
        while b"\r\n\r\n" not in data:
            part = c.recv(4096)
            if not part:
                return
            data += part
        head, body = data.split(b"\r\n\r\n", 1)
        cl = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                cl = int(line.split(b":", 1)[1].strip())
        while len(body) < cl:
            body += c.recv(4096)
        resp = dns_response(body[:cl])
        out = (b"HTTP/1.1 200 OK\r\n"
               b"Content-Type: application/dns-message\r\n"
               b"Content-Length: " + str(len(resp)).encode() +
               b"\r\nConnection: close\r\n\r\n" + resp)
        c.sendall(out)
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(16)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
