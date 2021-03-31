import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["mydatabase"]

db_merchants = mydb.merchants.find()

db_services = mydb.services.find({}, {'_id': 0})