import socket
import ssl
import struct

CERT = "/tmp/h2-cert.pem"
KEY = "/tmp/h2-key.pem"

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
ctx.set_alpn_protocols(["h2"])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 8445))
s.listen()

while True:
    conn, _ = s.accept()
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
        # Preface (24) + client SETTINGS/HEADERS; just drain.
        tls.recv(4096)
        # Server SETTINGS: empty.
        tls.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        # HPACK static index 8 = :status 200.
        block = b"\x88"
        tls.sendall(b"\x00\x00\x01\x01\x04\x00\x00\x00\x01" + block)
        # DATA "hello", END_STREAM.
        tls.sendall(b"\x00\x00\x05\x00\x01\x00\x00\x00\x01hello")
        tls.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
