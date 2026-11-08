import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",11211)); s.listen()
while True:
 c,_=s.accept()
 try:
  c.recv(4096); c.sendall(b"VERSION 1.6.21\r\n"); c.close()
 except Exception: c.close()
