import hashlib


def dedup_key(payload):
    # A cache/dedup identifier, not a security control.
    return hashlib.sha1(payload, usedforsecurity=False).hexdigest()
