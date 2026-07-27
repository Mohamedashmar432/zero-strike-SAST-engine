# ZS-PY-067: RC4 is a broken stream cipher (keystream biases)
from Crypto.Cipher import ARC4
cipher = ARC4.new(b'0123456789abcdef')
