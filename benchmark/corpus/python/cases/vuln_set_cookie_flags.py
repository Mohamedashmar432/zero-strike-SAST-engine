# ZS-PY-098 and ZS-PY-099: an auth cookie set with Django/Flask defaults,
# which are httponly=False and secure=False.
def login(request, response, token):
    response.set_cookie("auth_token", token)
    return response
