import sqlite3

from fastapi import FastAPI

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


# The helper's parameter only ever receives a constant from the route and the
# framework binds nothing to it: no finding.
@app.get("/admin")
def get_admin():
    return lookup("admin")


def lookup(role):
    cursor.execute("SELECT * FROM users WHERE role = '" + role + "'")
    return {"ok": True}
