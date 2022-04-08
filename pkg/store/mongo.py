import bcrypt
import logging

from pymongo import MongoClient

from pkg import config
from pkg.store.abstract import AbstractStore

logger=  logging.getLogger('pkg.store.mongo')

# Hash the user's password before storing
def hash_password(raw_password):
    password = raw_password
    hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
    return hashed.decode()


USER_ACCOUNTS_COLLECTION_NAME = 'users'
APPSPECS_COLLECTION_NAME = 'appspecs'
USERAPPS_COLLECTION_NAME = 'userapps'

VOCABULARIES_COLLECTION_NAME = 'vocabularies'

def serialize_id(entity):
    #if entity is None:
    #    return entity
    #entity['_id'] = str(entity['_id'])
    return entity


def finalize_id(entity, inserted_id):
    if entity is None or inserted_id is None:
        return entity

    entity['_id'] = str(inserted_id)
    return entity


class MongoStore(AbstractStore):

    # Sets up a new MongoClient with the given parameters
    def __init__(self, host=config.MONGO_HOST, port=config.MONGO_PORT):
        self.client = MongoClient(host=host, port=port)
        self.db = self.client[config.MONGO_DATABASE]

    # UserAccounts
    def create_user(self, new_user):
        created = self.db[USER_ACCOUNTS_COLLECTION_NAME].insert_one(new_user)
        return finalize_id(new_user, created.inserted_id)

    def fetch_users(self):
        return list(self.db[USER_ACCOUNTS_COLLECTION_NAME].find())

    def retrieve_user_by_username(self, username):
        return serialize_id(self.db[USER_ACCOUNTS_COLLECTION_NAME].find_one({'username': username}))

    def update_user(self, updated_user):
        return serialize_id(self.db[USER_ACCOUNTS_COLLECTION_NAME].update_one({'username': updated_user['username']}, updated_user))

    def delete_user(self, username):
        deleted = self.db[USER_ACCOUNTS_COLLECTION_NAME].delete_one({'username': username})
        return deleted.deleted_count

    # AppSpecs
    def fetch_all_appspecs_for_user(self, username):
        #return self.fetch_system_appspecs().update(self.fetch_user_appspecs(username))
        return self.fetch_system_appspecs() + self.fetch_user_appspecs(username)

    def create_system_appspec(self, new_appspec):
        new_appspec['catalog'] = 'system'
        created = self.db[APPSPECS_COLLECTION_NAME].insert_one(new_appspec)
        return finalize_id(new_appspec, created.inserted_id)

    def create_user_appspec(self, new_appspec):
        new_appspec['catalog'] = 'user'
        created = self.db[APPSPECS_COLLECTION_NAME].insert_one(new_appspec)
        return finalize_id(new_appspec, created.inserted_id)

    def fetch_user_appspecs(self, username):
        user_specs = list(self.db[APPSPECS_COLLECTION_NAME].find({'catalog': 'user',
                                                                  'creator': username}))
        return user_specs   # self.to_spec_map(user_specs)

    def fetch_system_appspecs(self):
        system_specs = list(self.db[APPSPECS_COLLECTION_NAME].find({'catalog': 'system'}))
        return system_specs   # self.to_spec_map(system_specs)

    def retrieve_user_appspec_by_key(self, username, spec_key):
        return serialize_id(self.db[APPSPECS_COLLECTION_NAME].find_one({'key': spec_key,
                                                           'catalog': 'user',
                                                           'creator': username}))

    def retrieve_system_appspec_by_key(self, spec_key):
        return serialize_id(self.db[APPSPECS_COLLECTION_NAME].find_one({'key': spec_key,
                                                           'catalog': 'system'}))

    def update_user_appspec(self, username, updated_appspec):
        updated_appspec['catalog'] = 'user'
        updated_appspec['creator'] = username
        spec_key = updated_appspec['key']
        updated = self.db[APPSPECS_COLLECTION_NAME].update_one(filter={'key': spec_key,
                                                             'catalog': 'user',
                                                             'creator': username}, update={'$set': updated_appspec})
        if updated.matched_count != updated.modified_count:
            logger.warning('Warning: matched_docs=%d, but modified_docs=%d during update of %s appspec with key=%s' %
                           (updated.matched_count, updated.modified_count, 'user', spec_key))

        return updated_appspec

    def update_system_appspec(self, updated_appspec):
        spec_key = updated_appspec['key']
        updated = self.db[APPSPECS_COLLECTION_NAME].update_one(filter={'key': spec_key,
                                                             'catalog': 'system'}, update={'$set': updated_appspec})

        if updated.matched_count != updated.modified_count:
            logger.warning('Warning: matched_docs=%d, but modified_docs=%d during update of %s appspec with key=%s' %
                           (updated.matched_count, updated.modified_count, 'user', spec_key))
        return updated_appspec

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
        return finalize_id(new_userapp, created.inserted_id)

    def fetch_userapps(self, username):
        return list(self.db[USERAPPS_COLLECTION_NAME].find({'creator': username}))

    def retrieve_userapp_by_id(self, username, userapp_id):
        return serialize_id(self.db[USERAPPS_COLLECTION_NAME].find_one({'id': userapp_id,
                                                           'creator': username}))

    def update_userapp(self, updated_userapp):
        return serialize_id(self.db[APPSPECS_COLLECTION_NAME].update_one({'id': updated_userapp['id'],
                                                             'creator': updated_userapp['creator']}, updated_userapp))

    def delete_userapp(self, username, userapp_id):
        deleted = self.db[APPSPECS_COLLECTION_NAME].delete_one({'id': userapp_id,
                                                                'creator': username})
        return deleted.deleted_count

    # Vocabulary
    def fetch_vocab_by_name(self, vocab_name):
        return serialize_id(self.db[VOCABULARIES_COLLECTION_NAME].find_one({'name': vocab_name}))
