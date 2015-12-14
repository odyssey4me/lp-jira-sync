from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017/')

db = client['lp_jira_sync']
