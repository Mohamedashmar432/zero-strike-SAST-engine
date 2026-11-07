# ZS-PY-028: a leading "/" followed by an expression can supply a second slash
# ("//evil.example"), so the local-path gate must not clear this.
from flask import redirect, request


def go():
    nxt = request.args.get("next")
    return redirect("/" + nxt)
