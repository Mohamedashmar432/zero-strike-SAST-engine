# ZS-PY-056: hashlib.new selecting a broken algorithm by name
import hashlib


def fingerprint(data):
    h = hashlib.new("md5")
    h.update(data)
    return h.hexdigest()
