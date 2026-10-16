# ZS-PY-011: usedforsecurity=True must not suppress the weak-hash finding
import hashlib

digest = hashlib.sha1(b"payload", usedforsecurity=True).hexdigest()
