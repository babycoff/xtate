import socket
import struct

def name_list(value):
    raw = value.encode("ascii")
    return struct.pack(">I", len(raw)) + raw

def kexinit():
    kex = "curve25519-sha256,ext-info-c"
    host_key = "ssh-ed25519,rsa-sha2-512"
    payload = b"\x14" + b"\x00" * 16
    payload += name_list(kex)
    payload += name_list(host_key)
    payload += name_list("aes128-ctr")
    payload += name_list("aes128-ctr")
    payload += name_list("hmac-sha2-256")
    payload += name_list("hmac-sha2-256")
    payload += name_list("none")
    payload += name_list("none")
    payload += name_list("")
    payload += name_list("")
    payload += b"\x00"                 # first_kex_packet_follows
    payload += b"\x00\x00\x00\x00"     # reserved
    padding_len = 4
    packet_len = 1 + len(payload) + padding_len
    return (struct.pack(">I", packet_len) + bytes([padding_len]) +
            payload + b"\x00" * padding_len)

banner = b"SSH-2.0-OpenSSH_9.9\r\n"
packet = kexinit()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 2222))
s.listen()
while True:
    conn, _ = s.accept()
    conn.sendall(banner + packet)
    conn.close()
