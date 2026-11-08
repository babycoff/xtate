import os
import socket
import ssl

CERT = "/tmp/h2-cert.pem"
KEY = "/tmp/h2-key.pem"

STATUS = int(os.environ.get("H2_STATUS", "200"))
EMPTY_DATA = os.environ.get("H2_EMPTY_DATA", "") not in ("", "0", "false")
DATA = os.environ.get("H2_DATA", "hello").encode()
EXTRA = os.environ.get("H2_EXTRA_HEADER", "")

STATUS_HPACK = {
    200: 0x88, 204: 0x89, 206: 0x8A, 304: 0x8B,
    400: 0x8C, 404: 0x8D, 500: 0x8E,
}


def frame(ftype, flags, stream, payload):
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
            + stream.to_bytes(4, "big") + payload)


def hpack_extra(name_value):
    if not name_value or ":" not in name_value:
        return b""
    name, value = name_value.split(":", 1)
    name = name.strip().encode()
    value = value.strip().encode()
    # Literal Header Field without Indexing, new name; HPACK string format.
    return bytes([0x00, len(name)]) + name + bytes([len(value)]) + value


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
        tls.sendall(frame(4, 0, 0, b""))
        block = bytes([STATUS_HPACK.get(STATUS, 0x88)]) + hpack_extra(EXTRA)
        tls.sendall(frame(1, 0x04, 1, block))
        if not EMPTY_DATA:
            tls.sendall(frame(0, 0x01, 1, DATA))
        tls.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
