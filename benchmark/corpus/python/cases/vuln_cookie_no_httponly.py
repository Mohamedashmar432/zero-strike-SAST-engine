# ZS-PY-098: Secure is set, HttpOnly is not, so this is the only flag reported
# (ZS-PY-099 must stay silent here).
def login(request, response, token):
    response.set_cookie("auth_token", token, secure=True)
    return response
