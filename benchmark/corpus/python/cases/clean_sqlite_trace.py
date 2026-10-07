# True negative for ZS-PY-078: tracing switched off, and a custom callback
# that records only the statement verb.
import sqlite3

STATS = {}


def count_statement(sql):
    verb = sql.split(' ', 1)[0].upper()
    STATS[verb] = STATS.get(verb, 0) + 1


conn = sqlite3.connect('app.db')
conn.set_trace_callback(None)
conn.set_trace_callback(count_statement)
