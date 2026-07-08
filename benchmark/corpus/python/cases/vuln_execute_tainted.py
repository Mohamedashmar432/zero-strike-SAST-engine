# ZS-PY-004: cursor.execute() call with a tainted argument (source: request.args)
user_id = request.args.get('id')
query = "SELECT " + user_id
cursor.execute(query)
