import jwt
from flask import request

incoming = request.headers.get('Authorization', '')
decoded = jwt.decode(incoming, options={"require": []}, algorithms=['none'])
