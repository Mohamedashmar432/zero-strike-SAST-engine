# ZS-PY-004: execute() call with a tainted argument (source: request.args)
user_id = request.args.get('id')
query = "SELECT " + user_id
execute(query)
