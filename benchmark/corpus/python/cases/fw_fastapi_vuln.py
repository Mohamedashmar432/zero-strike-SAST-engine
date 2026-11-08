import sqlite3

from fastapi import FastAPI

app = FastAPI()
cursor = sqlite3.connect("app.db").cursor()


@app.get("/user")
def get_user(user_id: str):
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    return {"ok": True}
