import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 8082))
while True:
    data, addr = s.recvfrom(4096)
    s.sendto(b"echo:" + data, addr)
