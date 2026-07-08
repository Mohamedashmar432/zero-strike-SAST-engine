import jwt

payload = {'username': 'guest'}
token = jwt.encode(payload, '', algorithm='none')
