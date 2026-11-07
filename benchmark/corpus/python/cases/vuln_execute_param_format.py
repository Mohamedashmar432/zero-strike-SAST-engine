# ZS-PY-004: a parameter formatted into the query string still fires.
def find(name):
    query = "SELECT * FROM t WHERE n = '%s'" % name
    cursor.execute(query)
