# True negative for ZS-PY-098/099: both flags set, and a cookie being cleared.
def login(request, response, token):
    response.set_cookie("auth_token", token, secure=True, httponly=True, samesite="Lax")
    response.set_cookie("auth_token", "", max_age=0)
    return response
