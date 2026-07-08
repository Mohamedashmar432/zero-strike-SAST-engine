# ZS-PY-030: CORS misconfiguration — Origin header reflected back unchecked
origin = request.headers.get('Origin', '*')
response.headers['Access-Control-Allow-Origin'] = origin
