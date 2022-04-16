import bcrypt
import connexion
import logging

from pkg.db import mongo
from pkg.auth import jwt
from pkg.db.datastore import data_store


logger = logging.getLogger('api.v1.user_accounts')


# TODO: Different default resource levels?
DEFAULT_DEV_RESOURCE_QUOTA = {
    # CPU / RAM
    "requests.cpu": "2",
    "requests.memory": "1G",
    "limits.cpu": "4",
    "limits.memory": "2G",

    # Userdata storage volume
    "requests.storage": "10Gi",

    # Kubernetes (external) networking
    # "services.nodeports": "0",
    # "services.loadbalancers": "0",

    # Kubernetes (internal) networking/execution
    # "services": "8",
    # "pods": "8",
    # "replicationcontrollers": "8",
    # "resourcequotas": "0",
    # "secrets": "0",
    # "configmaps": "0",
    # "persistentvolumeclaims": "0",
}


def list_accounts():
    users = data_store.fetch_users()
    return users, 200


def create_account(accounts):
    # TODO: Can we generate this from swagger?
    if 'username' not in accounts:
        return 'Username is required', 400
    if 'password' not in accounts:
        return 'Password is required', 400
    if 'email' not in accounts:
        return 'Email is required', 400
    if 'name' not in accounts:
        return 'Name is required', 400

    username = accounts['username']
    password = accounts['password']

    # Hash / salt account password
    hashed_password = bcrypt.hashpw(password.encode('ascii'), bcrypt.gensalt())
    accounts['password'] = hashed_password

    # Ensure that user doesn't already exist
    existing_user = data_store.retrieve_user_by_namespace(username)
    if existing_user is not None:
        return 'User account already exists: %s' % existing_user['username'], 400

    # User has been created, now create k8s resources
    # kube.init_user(username)

    # Create user account in data store
    result = data_store.create_user(accounts)
    accounts['id'] = result.inserted_id

    return mongo.parse_json(accounts), 201


def get_account_by_id(account_id):
    user = data_store.retrieve_user_by_namespace(account_id)
    if user is None:
        return {'error': 'Not found username=%s' % account_id}, 404
    user['_id'] = str(user['_id'])
    del user['password']
    return user, 200


def change_password(password):
    account_info = connexion.request.json
    logger.info(account_info)

    # Use token auth claims to fetch account
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = claims['username']
    account = data_store.retrieve_user_by_namespace(username)

    # Hash / salt new password
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

    # Only modify password field
    account.password = hashed_password
    result = data_store.update_user(account)

    return account, 200


def update_account(account_id, account):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)

    if account_id != account['id']:
        return 'error: account id mismatch', 400

    # Admins only: check token for required role
    if username != account_id:
        jwt.validate_scopes(['workbench-accounts'], claims)

    # Make sure user can't change password like this
    existing_account = data_store.retrieve_user_by_namespace(account.id)
    account.password = existing_account.password
    return mongo.parse_json(data_store.update_user(account)), 200


def delete_account(account_id):
    token = jwt.get_token()
    claims = jwt.safe_decode(token)
    username = jwt.get_username_from_token(token)

    # Admins only: check token for required role
    if username != account_id:
        jwt.validate_scopes(['workbench-accounts'], claims)

    return data_store.delete_user(account_id)


def register_user(account):
    # TODO: User signup workflow
    return '', 501


def verify_email_address(verify):
    # TODO: User signup workflow
    return '', 501


def send_reset_password_email(userId):
    return '', 501

