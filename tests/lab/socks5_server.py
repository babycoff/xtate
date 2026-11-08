import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("0.0.0.0",1080)); s.listen()
while True:
 c,_=s.accept()
 try:
  c.recv(4096); c.sendall(b"\x05\x00"); c.close()
 except Exception: c.close()
