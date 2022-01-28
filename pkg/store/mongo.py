import bcrypt

from pymongo import MongoClient

from pkg import config
from pkg.store.abstract import AbstractStore


# Hash the user's password before storing
def hash_password(raw_password):
    password = raw_password
    hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
    return hashed.decode()


USER_ACCOUNTS_COLLECTION_NAME = 'users'
APPSPECS_COLLECTION_NAME = 'appspecs'
USERAPPS_COLLECTION_NAME = 'userapps'

VOCABULARIES_COLLECTION_NAME = 'vocabularies'


class MongoStore(AbstractStore):

    # Sets up a new MongoClient with the given parameters
    def __init__(self, host=config.MONGO_HOST, port=config.MONGO_PORT):
        self.client = MongoClient(host=host, port=port)
        self.db = self.client[config.MONGO_DATABASE]

    # UserAccounts
    def create_user(self, new_user):
        return self.db[USER_ACCOUNTS_COLLECTION_NAME].insert_one(new_user)

    def fetch_users(self):
        return list(self.db[USER_ACCOUNTS_COLLECTION_NAME].find())

    def retrieve_user_by_namespace(self, namespace):
        return self.db[USER_ACCOUNTS_COLLECTION_NAME].find_one({'namespace': namespace})

    def update_user(self, updated_user):
        return self.db[USER_ACCOUNTS_COLLECTION_NAME].update_one({'namespace': updated_user['namespace']}, updated_user)

    def delete_user(self, namespace):
        return self.db[USER_ACCOUNTS_COLLECTION_NAME].delete_one({'namespace': namespace})

    # AppSpecs
    def fetch_all_appspecs_for_user(self, namespace):
        return self.fetch_system_appspecs() + self.fetch_user_appspecs(namespace)

    def create_system_appspec(self, new_appspec):
        new_appspec['catalog'] = 'system'
        return self.db[APPSPECS_COLLECTION_NAME].insert_one(new_appspec)

    def create_user_appspec(self, new_appspec):
        new_appspec['creator'] = namespace
        new_appspec['catalog'] = 'user'
        return self.db[APPSPECS_COLLECTION_NAME].insert_one(new_appspec)

    def fetch_user_appspecs(self, namespace):
        return list(self.db[APPSPECS_COLLECTION_NAME].find({'catalog': 'user',
                                                            'creator': namespace}))

    def fetch_system_appspecs(self):
        return list(self.db[APPSPECS_COLLECTION_NAME].find({'catalog': 'system'}))

    def retrieve_user_appspec_by_key(self, namespace, spec_key):
        return self.db[APPSPECS_COLLECTION_NAME].find_one({'key': spec_key,
                                                           'catalog': 'user',
                                                           'creator': namespace})

    def retrieve_system_appspec_by_key(self, spec_key):
        return self.db[APPSPECS_COLLECTION_NAME].find_one({'key': spec_key,
                                                           'catalog': 'system'})

    def update_user_appspec(self, namespace, updated_appspec):
        return self.db[APPSPECS_COLLECTION_NAME].update_one({'key': updated_appspec['key'],
                                                             'catalog': 'user',
                                                             'creator': namespace}, updated_appspec)

    def update_system_appspec(self, updated_appspec):
        return self.db[APPSPECS_COLLECTION_NAME].update_one({'key': updated_appspec['key'],
                                                             'catalog': 'system'}, updated_appspec)

    def delete_user_appspec(self, namespace, spec_key):
        return self.db[APPSPECS_COLLECTION_NAME].delete_one({'key': spec_key,
                                                             'catalog': 'user',
                                                             'creator': namespace})

    def delete_system_appspec(self, spec_key):
        return self.db[APPSPECS_COLLECTION_NAME].delete_one({'key': spec_key,
                                                             'catalog': 'system'})

    # UserApps
    def create_userapp(self, new_userapp):
        return self.db[USERAPPS_COLLECTION_NAME].insert_one(new_userapp)

    def fetch_userapps(self, namespace):
        return list(self.db[USERAPPS_COLLECTION_NAME].find({'creator': namespace}))

    def retrieve_userapp_by_id(self, namespace, userapp_id):
        return self.db[USERAPPS_COLLECTION_NAME].find_one({'id': userapp_id,
                                                           'creator': namespace})

    def update_userapp(self, updated_userapp):
        return self.db[APPSPECS_COLLECTION_NAME].update_one({'id': updated_userapp['id'],
                                                             'creator': updated_userapp['creator']}, updated_userapp)

    def delete_userapp(self, namespace, userapp_id):
        return self.db[APPSPECS_COLLECTION_NAME].delete_one({'id': userapp_id,
                                                             'creator': namespace})




