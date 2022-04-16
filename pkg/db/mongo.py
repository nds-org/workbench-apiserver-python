import bcrypt
import datetime
import json
import logging

from pymongo import MongoClient
from bson import json_util, ObjectId

from pkg import config
from pkg.auth import jwt

logger = logging.getLogger('pkg.store.mongo')


# Hash the user's password before storing
def hash_password(raw_password):
    password = raw_password
    hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
    return hashed.decode()


USER_ACCOUNTS_COLLECTION_NAME = 'users'
APPSPECS_COLLECTION_NAME = 'appspecs'
USERAPPS_COLLECTION_NAME = 'userapps'

REFRESHTOKENS_COLLECTION_NAME = 'refreshtokens'
VOCABULARIES_COLLECTION_NAME = 'vocabularies'


class MongoStore:

    @staticmethod
    def finalize_id(entity, inserted_id):
        if entity is not None and inserted_id is not None:
            entity['_id'] = str(inserted_id)

        return MongoStore.serialize(entity)

    @staticmethod
    def serialize(entity):
        return MongoStore.from_json(MongoStore.to_json(entity))

    @staticmethod
    def to_json(obj) -> str:
        return json.dumps(obj, default=json_util.default)

    @staticmethod
    def from_json(json_str) -> object:
        return json.loads(json_str)   # , object_hook=json_util.object_hook)

    # Sets up a new MongoClient with the given URI
    def __init__(self):
        self.client = MongoClient(config.MONGO_URI, authSource='admin')
        self.db = self.client[config.MONGO_DB]

    # RefreshToken
    def store_refresh_token(self, token_info, refresh_token):
        sid = token_info['session_state']
        refr_token_info = jwt.decode_refresh_token(refresh_token)
        refr_token_info['token'] = refresh_token
        refr_token_info['expiresAt'] = datetime.datetime.fromtimestamp(refr_token_info['exp'])
        upsert = self.db[REFRESHTOKENS_COLLECTION_NAME].update_one({'session_state': sid},
                                                                   {'$set': refr_token_info},
                                                                   upsert=True)
        return MongoStore.finalize_id(refr_token_info, upsert.upserted_id)

    def clear_refresh_token(self, token_info):
        return self.db[REFRESHTOKENS_COLLECTION_NAME].delete_one({'session_state': token_info['session_state']})

    def retrieve_refresh_token(self, token_info):
        return self.db[REFRESHTOKENS_COLLECTION_NAME].find_one({'session_state': token_info['session_state']})

    # UserAccounts
    def create_user(self, new_user):
        created = self.db[USER_ACCOUNTS_COLLECTION_NAME].insert_one(new_user)
        return MongoStore.finalize_id(new_user, created.inserted_id)

    def fetch_users(self):
        return list(self.db[USER_ACCOUNTS_COLLECTION_NAME].find())

    def retrieve_user_by_username(self, username):
        user = self.db[USER_ACCOUNTS_COLLECTION_NAME].find_one({'username': username})
        return MongoStore.serialize(user)

    def update_user(self, updated_user):
        username = updated_user['username']
        updated = self.db[USER_ACCOUNTS_COLLECTION_NAME].update_one(filter={'username': username},
                                                                    update={'$set': updated_user})
        return updated.modified_count

    def delete_user(self, username):
        deleted = self.db[USER_ACCOUNTS_COLLECTION_NAME].delete_one({'username': username})
        return deleted.deleted_count

    # AppSpecs
    def fetch_all_appspecs_for_user(self, username):
        return self.fetch_system_appspecs() + self.fetch_user_appspecs(username)

    def create_system_appspec(self, new_appspec):
        new_appspec['catalog'] = 'system'
        created = self.db[APPSPECS_COLLECTION_NAME].insert_one(new_appspec)
        return MongoStore.finalize_id(new_appspec, created.inserted_id)

    def create_user_appspec(self, new_appspec):
        new_appspec['catalog'] = 'user'
        created = self.db[APPSPECS_COLLECTION_NAME].insert_one(new_appspec)
        return MongoStore.finalize_id(new_appspec, created.inserted_id)

    def fetch_user_appspecs(self, username):
        return list(self.db[APPSPECS_COLLECTION_NAME].find({'catalog': 'user',
                                                            'creator': username}))

    def fetch_system_appspecs(self):
        return list(self.db[APPSPECS_COLLECTION_NAME].find({'catalog': 'system'}))

    def retrieve_user_appspec_by_key(self, username, spec_key):
        appspec = self.db[APPSPECS_COLLECTION_NAME].find_one({'key': spec_key,
                                                              'catalog': 'user',
                                                              'creator': username})
        return MongoStore.serialize(appspec)

    def retrieve_system_appspec_by_key(self, spec_key):
        appspec = self.db[APPSPECS_COLLECTION_NAME].find_one({'key': spec_key,
                                                              'catalog': 'system'})
        return MongoStore.serialize(appspec)

    def update_user_appspec(self, username, updated_appspec):
        updated_appspec['catalog'] = 'user'
        updated_appspec['creator'] = username
        spec_key = updated_appspec['key']
        updated = self.db[APPSPECS_COLLECTION_NAME].update_one(filter={'key': spec_key,
                                                               'catalog': 'user',
                                                               'creator': username}, update={'$set': updated_appspec})
        return updated.modified_count

    def update_system_appspec(self, updated_appspec):
        spec_key = updated_appspec['key']
        updated = self.db[APPSPECS_COLLECTION_NAME].update_one(filter={'key': spec_key,
                                                               'catalog': 'system'}, update={'$set': updated_appspec})

        return updated.modified_count

    def delete_user_appspec(self, username, spec_key):
        deleted = self.db[APPSPECS_COLLECTION_NAME].delete_one({'key': spec_key,
                                                                'catalog': 'user',
                                                                'creator': username})
        return deleted.deleted_count

    def delete_system_appspec(self, spec_key):
        deleted = self.db[APPSPECS_COLLECTION_NAME].delete_one({'key': spec_key,
                                                                'catalog': 'system'})
        return deleted.deleted_count

    # UserApps
    def create_userapp(self, new_userapp):
        created = self.db[USERAPPS_COLLECTION_NAME].insert_one(new_userapp)
        return MongoStore.finalize_id(new_userapp, created.inserted_id)

    def fetch_userapps(self, username):
        return list(self.db[USERAPPS_COLLECTION_NAME].find({'creator': username}))

    def retrieve_userapp_by_id(self, username, userapp_id):
        userapp = self.db[USERAPPS_COLLECTION_NAME].find_one({'id': userapp_id,
                                                              'creator': username})
        return MongoStore.serialize(userapp)

    def update_userapp(self, updated_userapp):
        userapp_id = updated_userapp['id']
        username = updated_userapp['creator']
        updated = self.db[APPSPECS_COLLECTION_NAME].update_one({'id': userapp_id,
                                                                'creator': username}, {'$set': updated_userapp})

        return updated.modified_count

    def delete_userapp(self, username, userapp_id):
        deleted = self.db[APPSPECS_COLLECTION_NAME].delete_one({'id': userapp_id,
                                                                'creator': username})
        return deleted.deleted_count

    # Vocabulary
    def fetch_vocab_by_name(self, vocab_name):
        vocabulary = self.db[VOCABULARIES_COLLECTION_NAME].find_one({'name': vocab_name})
        return MongoStore.serialize(vocabulary)
