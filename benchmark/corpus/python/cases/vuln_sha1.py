# ZS-PY-011: hashlib.sha1() used for password hashing (weak, no salt)
import hashlib
hashlib.sha1(password.encode())
