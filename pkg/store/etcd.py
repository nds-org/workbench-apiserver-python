import logging

import etcd
import json
import bcrypt

import pkg.config as config
from pkg.store.abstract import AbstractStore

logger = logging.getLogger('EtcdStore')


def get_accounts_path():
    return config.ETCD_BASE_PATH + "/accounts"


def get_system_appspecs_path():
    return config.ETCD_BASE_PATH + "/services"


def get_user_apps_path(username):
    return get_accounts_path() + "/" + username + "/stacks"


def get_user_appspecs_path(username):
    return get_accounts_path() + "/" + username + "/services"


def get_vocabularies_path():
    return config.ETCD_BASE_PATH + "/vocabularies"


class EtcdStore(AbstractStore):

    # Sets up a new etcd Client with the given parameters
    def __init__(self, host=config.ETCD_HOST, port=config.ETCD_PORT):
        self.client = etcd.Client(host=host, port=port)
        # wont let you run sensitive commands on non-leader machines, default is true
        # client = etcd.Client(host='127.0.0.1', port=4003, allow_redirect=False)
        # client = etcd.Client(
        #    host='127.0.0.1',
        #    port=4003,
        #    allow_reconnect=True,
        #    protocol='https',)

    def create_user(self, new_user):
        namespace = new_user.namespace
        new_user_path_prefix = get_accounts_path() + "/" + namespace

        try:
            # Create a new directory for this user
            self.client.write(new_user_path_prefix, new_user, None, True, False)

            # Create a new directory for this user's services/apps
            self.client.write(new_user_path_prefix + "/services", new_user, None, True, False)
            self.client.write(new_user_path_prefix + "/apps", new_user, None, True, False)

            # Insert the user account JSON
            self.client.write(new_user_path_prefix + "/account", new_user, None, False, False)
        except Exception as e:
            logger.error("Failed to create user in etcd:", e)

    def fetch_users(self):
        accounts_path = get_accounts_path()

        try:
            # Fetch a list of user accounts
            directory = self.client.get(accounts_path)

            return directory.children
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to fetch user accounts in etcd:", e)

    def retrieve_user_by_username(self, username):
        user_account_path = get_accounts_path() + "/" + username

        try:
            # Retrieve a user account by id
            return self.client.read(user_account_path)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to retrieve user by namespace in etcd:", e)

    def update_user(self, updated_user):
        namespace = updated_user['namespace']
        user_account_path = get_accounts_path() + "/" + namespace

        try:
            # Update a user account by id
            return self.client.write(user_account_path + "/account", updated_user, None, False, False)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to update user by namespace in etcd:", e)

    def delete_user(self, username):
        user_account_path = get_accounts_path() + "/" + username

        try:
            # Recursively delete a user account by id
            return self.client.delete(user_account_path, True, True, False)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to delete user by namespace in etcd:", e)

    def fetch_all_appspecs_for_user(self, namespace):
        system_specs = self.fetch_system_appspecs()
        user_specs = self.fetch_user_appspecs(namespace)
        return system_specs + user_specs

    def create_system_appspec(self, new_appspec):
        spec_key = new_appspec.key
        new_appspec_path_prefix = get_system_appspecs_path() + "/" + spec_key

        try:
            # Insert the appspec JSON
            self.client.write(new_appspec_path_prefix, new_appspec, None, False, False)
        except Exception as e:
            logger.error("Failed to create system appspec in etcd:", e)

    def create_user_appspec(self, new_appspec):
        spec_key = new_appspec.key
        username = new_appspec['creator']
        new_appspec_path_prefix = get_user_appspecs_path(username) + "/" + spec_key

        try:
            # Insert the appspec JSON
            self.client.write(new_appspec_path_prefix, new_appspec, None, False, False)
        except Exception as e:
            logger.error("Failed to create user appspec in etcd:", e)

    def fetch_user_appspecs(self, username):
        user_appspecs_path = get_user_appspecs_path(username)

        try:
            # Fetch a list of user appspecs
            directory = self.client.get(user_appspecs_path)
            return directory.children
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to fetch user appspecs in etcd:", e)

    def fetch_system_appspecs(self):
        system_appspecs_path = get_system_appspecs_path()

        try:
            # Fetch a list of system appspecs
            directory = self.client.get(system_appspecs_path)
            return directory.children
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to fetch system appspecs in etcd:", e)

    def retrieve_user_appspec_by_key(self, username, spec_key):
        user_appspec_path = get_user_appspecs_path(username) + "/" + spec_key

        try:
            # Retrieve a user appspec by key
            return self.client.read(user_appspec_path)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to retrieve user appspec by key in etcd:", e)

    def retrieve_system_appspec_by_key(self, spec_key):
        system_appspec_path = get_system_appspecs_path() + "/" + spec_key

        try:
            # Retrieve a system appspec by key
            return self.client.read(system_appspec_path)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to retrieve system appspec by key in etcd:", e)

    def update_user_appspec(self, username, updated_appspec):
        spec_key = updated_appspec['key']
        user_appspec_path = get_user_appspecs_path(username) + "/" + spec_key

        try:
            # Update a user appspec by key
            return self.client.write(user_appspec_path, updated_appspec, None, False, False)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to update user appspec by key in etcd:", e)

    def update_system_appspec(self, updated_appspec):
        spec_key = updated_appspec['key']
        system_appspec_path = get_system_appspecs_path() + "/" + spec_key

        try:
            # Update a system appspec by key
            return self.client.write(system_appspec_path, updated_appspec, None, False, False)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to update system appspec by key in etcd:", e)

    def delete_user_appspec(self, username, spec_key):
        user_appspec_path = get_user_appspecs_path(username) + "/" + spec_key

        try:
            # Recursively delete a user appspec by key
            return self.client.delete(user_appspec_path, True, True, False)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to delete user appspec by key in etcd:", e)

    def delete_system_appspec(self, spec_key):
        system_appspec_path = get_system_appspecs_path() + "/" + spec_key

        try:
            # Recursively delete a system appspec by key
            return self.client.delete(system_appspec_path, True, True, False)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to delete system appspec by key in etcd:", e)

    def create_userapp(self, new_userapp):
        userapp_id = new_userapp.id
        username = new_userapp['creator']
        new_userapp_path_prefix = get_user_apps_path(username) + "/" + userapp_id

        try:
            # Insert the new userapp JSON
            self.client.write(new_userapp_path_prefix, new_userapp, None, False, False)
        except Exception as e:
            logger.error("Failed to create userapp in etcd:", e)

    def fetch_userapps(self, username):
        userapps_path = get_user_apps_path(username)

        try:
            # Fetch a list of userapps for the given user
            directory = self.client.get(userapps_path)
            return directory.children
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to fetch userapps in etcd:", e)

    def retrieve_userapp_by_id(self, username, userapp_id):
        userapp_path = get_user_apps_path(username) + "/" + userapp_id

        try:
            # Retrieve a userapp by id
            return self.client.read(userapp_path)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to retrieve userapp by id in etcd:", e)

    def update_userapp(self, updated_userapp):
        userapp_id = updated_userapp['id']
        userapp_path = get_user_appspecs_path() + "/" + userapp_id

        try:
            # Update a userapp by id
            return self.client.write(userapp_path, updated_userapp, None, False, False)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to update userapp by key in etcd:", e)

    def delete_userapp(self, username, userapp_id):
        userapp_path = get_user_apps_path(username) + "/" + userapp_id

        try:
            # Delete a user app by id
            return self.client.delete(userapp_path, True, True, False)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to delete userapp by id in etcd:", e)

    # Vocabulary
    def fetch_vocab_by_name(self, vocab_name):
        vocab_path = get_vocabularies_path() + "/" + vocab_name

        try:
            # Retrieve a vocabulary by name
            return self.client.read(vocab_path)
        except etcd.EtcdKeyNotFound as e:
            logger.error("Failed to retrieve vocabulary by name in etcd:", e)

    ################################################################
    ################################################################
    ################################################################
    ################################################################
    ################################################################

    def get_system_services(self):
        def get_index(items):
            return items.get('modifiedIndex')

        key = config.ETCD_BASE_PATH + "/services"
        try:
            results = self.client.read(key)
        except etcd.EtcdKeyNotFound:
            return ''
        services = []

        for item in sorted(results._children, key=get_index):
            json_item = json.loads(item['value'])
            json_item['catalog'] = 'system'
            services.append(json_item)

        return services

    def get_user_services(self):
        def get_index(items):
            return items.get('modifiedIndex')

        # need to get uid
        uid = 'temp_id'
        key = config.ETCD_BASE_PATH + "/accounts/" + uid + "/services"
        try:
            results = self.client.read(key)
        except etcd.EtcdKeyNotFound:
            return ''
        services = []

        for item in sorted(results._children, key=get_index):
            json_item = json.loads(item['value'])
            json_item['catalog'] = 'user'
            services.append(json_item)

        return services

    def get_all_services(self):
        services = self.getSystemServices()
        services.append(self.getUserServices())

        return services

    def get_service_id_with(self, service_id):
        key = config.ETCD_BASE_PATH + "/services/" + service_id
        try:
            result = self.client.read(key)
        except etcd.EtcdKeyNotFound:
            return ''

        return json.loads(result.value)

    def get_account_info(self, account_id):
        key = config.ETCD_BASE_PATH + "/accounts/" + account_id + "/account"
        try:
            result = self.client.read(key)
        except etcd.EtcdKeyNotFound:
            return ''

        return json.loads(result.value)

    def set_account_info(self, account_info):
        key = config.ETCD_BASE_PATH + "/accounts/" + account_info['id'] + "/account"

        password = account_info['password']
        hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        account_info['password'] = hashed.decode()
        print(account_info)

        try:
            self.client.write(key, json.dumps(account_info))
            return True
        except NameError:
            return False

    def delete_account_info(self, account_id):
        key = config.ETCD_BASE_PATH + "/accounts/" + account_id + "/account"
        try:
            self.client.delete(key)
            return True
        except etcd.EtcdKeyNotFound:
            return ''

    def check_password(self, namespace, password):
        key = config.ETCD_BASE_PATH + "/accounts/" + namespace + "/account"

        try:
            result = self.client.read(key)
            result_value = json.loads(result.value)
            hashed = result_value.get('password')

            if bcrypt.checkpw(password.encode('utf8'), hashed.encode()):
                return True
            else:
                return False
        except etcd.EtcdKeyNotFound:
            return False
        except ValueError:
            return False

