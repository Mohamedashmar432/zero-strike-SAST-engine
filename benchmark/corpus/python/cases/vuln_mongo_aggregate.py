# ZS-PY-063: NoSQL injection via aggregate() with a tainted pipeline stage
stage = request.args.get('stage')
pipeline = [{"$match": {"name": stage}}]
collection.aggregate(pipeline)
