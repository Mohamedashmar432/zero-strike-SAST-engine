# ZS-PY-078: every executed SQL statement (with the values it carries) goes to
# stdout / the application log.
import logging
import sqlite3


def get_user(username):
    conn = sqlite3.connect('users.db')
    conn.set_trace_callback(print)
    return conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()


def get_posts():
    db = sqlite3.connect('posts.db')
    db.set_trace_callback(logging.debug)
    return db.execute('SELECT * FROM posts').fetchall()
