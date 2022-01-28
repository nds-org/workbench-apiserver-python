import logging
from pymongo import MongoClient
from bson import json_util
import json

from pkg import config


# logger = logging.getLogger('mongo')
# logger.info("     >>>>>>  Using " + config.MONGO_URI)
# mongo_client = MongoClient(config.MONGO_URI)
# db = mongo_client['workbench']


def get_mongo_client():
    return MongoClient(config.MONGO_HOST, username=config.MONGO_USER, password=config.MONGO_PASS)


def parse_json(data):
    return json.loads(json_util.dumps(data))