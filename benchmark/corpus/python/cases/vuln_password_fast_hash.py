# ZS-PY-096: a password stored as an unsalted SHA-256 digest. The from-import
# exercises import-alias canonicalization (sha256 -> hashlib.sha256).
from hashlib import sha256


def store_password(user, password):
    user.password_hash = sha256(password.encode()).hexdigest()
    user.save()
