# ZS-PY-029: weak crypto — DES has a 56-bit key and is trivially brute-forced
from Crypto.Cipher import DES
key = b'weakkey1'
cipher = DES.new(key, DES.MODE_ECB)
