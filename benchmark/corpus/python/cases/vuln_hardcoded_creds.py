import os
import hmac
import hashlib
import jwt
from cryptography.fernet import Fernet
from django.contrib.auth.hashers import make_password

db_config = dict(host="db.internal", password="Tr0ub4dor-fixture-pw")
API_SECRET = os.environ.get("API_SECRET", "fixture-fallback-secret-value")
DB_PASSWORD = os.getenv("DB_PASSWORD", "fixture-fallback-db-pass")
cipher = Fernet("fixture-fernet-key-not-real-0000000000000=")
mac = hmac.new(b"fixture-hmac-key-value", b"msg", hashlib.sha256)
hashed = make_password("fixture-user-pass-1")


def login(password):
    if password == "fixture-admin-pass-1":
        return jwt.encode({"user": "admin"}, "fixture-jwt-signing-key", algorithm="HS256")
    return None

encryption_key = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"
