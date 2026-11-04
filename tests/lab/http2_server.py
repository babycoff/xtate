import socket
import struct

# Server SETTINGS: MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=65535
settings_payload = struct.pack(">HI", 3, 100) + struct.pack(">HI", 4, 65535)
settings_frame = struct.pack(">I", len(settings_payload))[1:] + bytes([4, 0]) + b"\x00\x00\x00\x00" + settings_payload
# PING frame, stream 0
ping_frame = b"\x00\x00\x07\x06\x00\x00\x00\x00\x00" + b"xtate-2"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 8084))
s.listen()
while True:
    conn, _ = s.accept()
    conn.recv(4096)
    conn.sendall(settings_frame + ping_frame)
    conn.close()
