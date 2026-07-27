# ZS-PY-058: executescript() with a tainted SQL batch (no parameter binding exists)
table = request.args.get('table')
script = "DELETE FROM logs; DELETE FROM " + table
cursor.executescript(script)
