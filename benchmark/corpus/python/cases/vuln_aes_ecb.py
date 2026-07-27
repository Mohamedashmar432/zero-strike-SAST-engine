# ZS-PY-066: AES in ECB mode leaks plaintext structure (insecure mode)
from Crypto.Cipher import AES
key = b'0123456789abcdef'
cipher = AES.new(key, AES.MODE_ECB)
