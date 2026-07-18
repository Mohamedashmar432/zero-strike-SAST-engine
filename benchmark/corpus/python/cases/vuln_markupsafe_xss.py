# ZS-PY-054: Markup() marks tainted input as pre-escaped HTML (XSS)
from markupsafe import Markup
from flask import request

comment = request.args.get('comment', '')
html = Markup(comment)
