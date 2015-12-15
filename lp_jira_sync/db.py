from pymongo import MongoClient

from config import settings

client = MongoClient(host=settings.get('DB', 'host'),
                     port=settings.getint('DB', 'port'))

db = client['lp_jira_sync']
