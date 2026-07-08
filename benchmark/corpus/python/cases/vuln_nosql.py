import pymongo
from flask import request

client = pymongo.MongoClient('mongodb://localhost:27017/')
db_mongo = client['vulnerable_db']
collection = db_mongo['users']

query = request.args.get('q', '')
result = collection.find({"$where": f"this.username.includes('{query}')"})
