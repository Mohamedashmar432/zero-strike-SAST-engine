import socket

s = socket.socket()
s.connect(('localhost', 8080))
s.sendall(b'ping')
