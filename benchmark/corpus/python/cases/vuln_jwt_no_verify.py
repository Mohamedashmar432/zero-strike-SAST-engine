# ZS-PY-021: jwt.decode() with signature verification disabled
import jwt
payload = jwt.decode(token, verify=False)
