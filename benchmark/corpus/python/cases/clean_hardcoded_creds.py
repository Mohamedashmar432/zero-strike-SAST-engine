import os
import hmac
import hashlib
import jwt
from cryptography.fernet import Fernet

db_config = dict(host="db.internal", password=os.environ["DB_PASSWORD"])
template = dict(password="${DB_PASSWORD}")
placeholder = dict(password="changeme")
API_SECRET = os.environ.get("API_SECRET")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
cipher = Fernet(os.environ["FERNET_KEY"])
mac = hmac.new(os.environ["HMAC_KEY"].encode(), b"msg", hashlib.sha256)


def login(password, stored):
    if hmac.compare_digest(password, stored):
        return jwt.encode({"user": "u"}, os.environ["JWT_KEY"], algorithm="HS256")
    return None
