#!/usr/bin/env python3
"""Minimal HTTP/2 DoH server (no external h2 dependency)."""
import ssl, socket, struct, sys, threading

cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
ctx.set_alpn_protocols(["h2"])

def frame(t, flags, stream, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([t, flags]) + struct.pack(">I", stream) + payload

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

def read_frame(c):
    h = b""
    while len(h) < 9:
        p = c.recv(9 - len(h))
        if not p: return None
        h += p
    n = int.from_bytes(h[:3], "big")
    payload = b""
    while len(payload) < n:
        p = c.recv(n - len(payload))
        if not p: return None
        payload += p
    return h[3], h[4], int.from_bytes(h[5:9], "big") & 0x7fffffff, payload

def handle(c):
    try:
        c = ctx.wrap_socket(c, server_side=True)
        preface = b""
        while len(preface) < 24:
            preface += c.recv(24 - len(preface))
        c.sendall(frame(4, 0, 0, struct.pack(">HI", 3, 100) + struct.pack(">HI", 4, 65535)))
        body = b""
        while True:
            fr = read_frame(c)
            if not fr: return
            typ, flags, sid, payload = fr
            if typ == 4 and not (flags & 1):
                c.sendall(frame(4, 1, 0))
            elif typ == 0:
                body += payload
            elif typ == 1 and (flags & 4):
                # wait for the DATA frame on stream 1
                while True:
                    fr2 = read_frame(c)
                    if not fr2: return
                    t2, f2, s2, p2 = fr2
                    if t2 == 0:
                        body += p2
                        if f2 & 1:
                            break
                    elif t2 == 1:
                        continue
                resp = dns_response(body)
                # HPACK indexed :status 200 (static index 8), then DATA.
                c.sendall(frame(1, 4, 1, b"\x88") + frame(0, 1, 1, resp))
                return
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
