import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 2222))
s.listen()
while True:
    conn, _ = s.accept()
    conn.sendall(b"SSH-2.0-OpenSSH_9.9\r\n")
    conn.close()
