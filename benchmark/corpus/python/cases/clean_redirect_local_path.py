# True negative for ZS-PY-028: the destination starts with a literal local path
# and only the tail is dynamic, so the redirect cannot leave this origin.
from flask import redirect, request


def profile():
    user_id = request.args.get("id")
    return redirect("/users/" + str(user_id) + "/profile")
