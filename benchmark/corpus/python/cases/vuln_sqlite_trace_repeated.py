# ZS-PY-078: the same trace callback installed in several functions is one
# finding with an occurrence count, not one per function.
import sqlite3


def get_user(username):
    conn = sqlite3.connect('users.db')
    conn.set_trace_callback(print)
    return conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()


def get_posts():
    conn = sqlite3.connect('users.db')
    conn.set_trace_callback(print)
    return conn.execute('SELECT * FROM posts').fetchall()
