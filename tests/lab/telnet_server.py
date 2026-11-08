import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",2323)); s.listen()
while True:
 c,_=s.accept()
 try:
  c.sendall(b"\xff\xfd\x01\xff\xfb\x03login: ")
  c.close()
 except Exception: c.close()
