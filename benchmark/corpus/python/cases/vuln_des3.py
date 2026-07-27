# ZS-PY-068: 3DES is deprecated (Sweet32, NIST withdrawal)
from Crypto.Cipher import DES3
cipher = DES3.new(b'0123456789abcdef')
