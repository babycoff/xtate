import socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",12345))
while True:
 data,addr=s.recvfrom(2048)
 if len(data)>=48:
  r=bytearray(48); r[0]=0x24; r[1]=2; r[2]=6; r[3]=0xec
  r[12:16]=b"XTAT"; r[24:28]=data[40:44]
  s.sendto(r,addr)
