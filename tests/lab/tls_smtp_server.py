import socket
import ssl
import sys
import threading

CERT, KEY = sys.argv[1], sys.argv[2]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 2465))
srv.listen()
while True:
    conn, _ = srv.accept()
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
        tls.sendall(b"220 lab ESMTP\r\n")
        data = tls.recv(1024)
        if data:
            tls.sendall(b"250-lab\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
        tls.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
