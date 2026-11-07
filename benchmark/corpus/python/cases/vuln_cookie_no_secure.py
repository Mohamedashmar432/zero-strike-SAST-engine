# ZS-PY-099 is the one finding for a cookie missing Secure and HttpOnly: the
# call is reported once, not once per flag (ZS-PY-098 must stay silent here).
def login(request, response, token):
    response.set_cookie("auth_token", token)
    return response
