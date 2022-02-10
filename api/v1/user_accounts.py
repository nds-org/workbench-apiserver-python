import bcrypt
import connexion
import logging

from pkg import jwt
from pkg.datastore import data_store

logger = logging.getLogger('api.v1.user_accounts')

def list_accounts():
    users = data_store.fetch_users()
    return users, 200


def create_account(user):
    result = data_store.create_user(user)
    user.id = result.inserted_id
    return user, 201


def get_account_by_id(account_id):
    user = data_store.retrieve_user_by_namespace(account_id)
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
    account_info = connexion.request.json
    logger.info(account_info)

    if account_id != account.id:
        return 'error: account id mismatch', 400

    # Make sure user can't change password like this
    existing_account = data_store.retrieve_user_by_namespace(account.id)
    account.password = existing_account.password
    result = data_store.update_user(account)

    return account, 200


def delete_account(account_id):
    result = data_store.delete_user(account_id)
    return 204
