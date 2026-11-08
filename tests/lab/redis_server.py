import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",6380)); s.listen()
while True:
 c,_=s.accept()
 try:
  c.recv(4096)
  c.sendall(b"# Server\r\nredis_version:7.2.0\r\nredis_mode:standalone\r\nos:Linux\r\nrole:master\r\n")
  c.close()
 except Exception:
  c.close()
