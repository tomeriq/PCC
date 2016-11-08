import socket
import time

s = socket.socket()
TCP_CONGESTION = getattr(socket, 'TCP_CONGESTION', 13)
s.setsockopt(socket.IPPROTO_TCP, TCP_CONGESTION, "pcc")

s.connect(('10.1.1.4', 9999))

for i in range(100):
	s.sendall("a"*80700000)
