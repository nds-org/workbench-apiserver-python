#!/usr/bin/env python3

import json
import os
import sys
from pprint import pprint

import requests
from bson import json_util

from pymongo import MongoClient

# TODO: Pull these from pkg/config.py?
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/ndslabs')
MONGO_DB = os.getenv('MONGO_DB', 'ndslabs')

DEBUG = os.getenv('DEBUG', 'false').lower() in 'true'
FORCE = os.getenv('FORCE', 'false').lower() in 'true'

# TODO: Pull this from api/v1/app_specs.py?
APPSPECS_COLLECTION_NAME = 'appspecs'
VOCABULARIES_COLLECTION_NAME = 'vocabularies'


def read_file_json(file):
    # Opening JSON file
    with open(file) as f:
        json_data = f.read()
        return json.loads(json_data)


def import_all_specs(db, dir_path):
    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk(dir_path):
        path = root.split(os.sep)
        print((len(path) - 1) * '---', os.path.basename(root))
        for file in files:
            if os.path.basename(root) == 'vocab':
                rel_path = os.path.join(root, file)
                print(len(path) * '---', 'Importing vocab: ' + rel_path)
                import_vocab(db, rel_path)
            elif str.endswith(file, ".json"):
                rel_path = os.path.join(root, file)
                print(len(path) * '---', 'Importing spec: ' + rel_path)
                import_spec(db, rel_path)
            else: 
                print(len(path) * '---', 'Skipping file: ' + file)


def import_vocab(db, file):
    vocab = read_file_json(file)
    if 'name' not in vocab:
        print('Not a valid vocabulary: vocab "name" is missing. Skipping...')
        return
    vocab_name = vocab['name']
    existing_vocab = db[VOCABULARIES_COLLECTION_NAME].find_one(filter={'name': vocab_name})
    if existing_vocab and not FORCE:
        print('Spec already exists! Skipping...')
        return

    print('Applying spec...')
    replace_result = db[VOCABULARIES_COLLECTION_NAME].replace_one(filter={'name': vocab_name}, replacement=vocab, upsert=True)
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


def import_spec(db, file):
    app_spec = read_file_json(file)
    if 'key' not in app_spec:
        print('Not a valid spec: spec "key" is missing. Skipping...')
        return
    spec_key = app_spec['key']
    existing_spec = db[APPSPECS_COLLECTION_NAME].find_one(filter={'key': spec_key})
    if existing_spec and not FORCE:
        print('Spec already exists! Skipping...')
        return

    print('Applying spec...')
    app_spec['catalog'] = 'system'
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
        # print('Usage: ./test/specs/loadspecs.py path/to/appspec/file.json')
        print('Usage: ./loadspecs.py path/to/appspecs/dir/')
    else:
        file_path = args[1]
        print("Importings spec from: " + file_path)
        with MongoClient(MONGO_URI) as client:
            db = client.get_database(MONGO_DB)
            import_all_specs(db, file_path)
