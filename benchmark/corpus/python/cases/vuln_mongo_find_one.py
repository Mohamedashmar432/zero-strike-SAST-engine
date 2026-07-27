# ZS-PY-062: NoSQL injection via find_one() with a tainted filter
username = request.args.get('username')
collection.find_one({"username": username})
