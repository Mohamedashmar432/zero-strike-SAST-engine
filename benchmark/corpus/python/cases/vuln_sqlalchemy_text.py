# ZS-PY-060: SQLAlchemy text() wrapping a tainted SQL fragment
from sqlalchemy import text
name = request.args.get('name')
query = text("SELECT * FROM users WHERE name = '" + name + "'")
