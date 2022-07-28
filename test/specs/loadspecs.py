#!/usr/bin/env python3

import json
import os
import sys
from pprint import pprint
from bson import json_util

from pymongo import MongoClient

# TODO: Pull these from pkg/config.py?
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/ndslabs')
MONGO_DB = os.getenv('MONGO_DB', 'ndslabs')

DEBUG = os.getenv('DEBUG', 'false').lower() in 'true'
FORCE = os.getenv('FORCE', 'false').lower() in 'true'

# TODO: Pull this from api/v1/app_specs.py?
APPSPECS_COLLECTION_NAME = 'appspecs'


def read_file_json(file_path):
    # Opening JSON file
    with open(file_path) as f:
        json_data = f.read()
        return json.loads(json_data)


def import_spec(file_path):
    app_spec = read_file_json(file_path)
    spec_key = app_spec['key']
    with MongoClient(MONGO_URI) as client:
        db = client.get_database(MONGO_DB)
        existing_spec = db[APPSPECS_COLLECTION_NAME].find_one(filter={'key': spec_key})
        if existing_spec and not FORCE:
            print('Spec already exists! stopping...')
            return

        print('Applying spec...')
        replace_result = db[APPSPECS_COLLECTION_NAME].replace_one(filter={'key': spec_key}, replacement=app_spec, upsert=True)
        if replace_result.modified_count == replace_result.matched_count:
            print('import successful!')
        else:
            print('something went wrong')

            if DEBUG:
                print('matched:     ' + str(replace_result.matched_count))
                print('modified:    ' + str(replace_result.modified_count))
                print('upserted_id: ' + str(replace_result.upserted_id))
                print('acknowledged:' + str(replace_result.acknowledged))

        return



if __name__ == '__main__':
    args = sys.argv
    if len(args) == 0:
        print('Usage: ./test/specs/loadspec.py path/to/appspec/file.json')
    else:
        file_path = args[1]
        print("Importing spec from: " + file_path)
        import_spec(file_path)
