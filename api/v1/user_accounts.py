import bcrypt
import connexion
import logging

from pkg import jwt, mongo
from pkg.datastore import data_store

logger = logging.getLogger('api.v1.user_accounts')

def list_accounts():
    users = data_store.fetch_users()
    return users, 200


def create_account(accounts):
    result = data_store.create_user(accounts)
    accounts['id'] = result.inserted_id
    return mongo.parse_json(accounts), 201


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


def register_user(account):
    # TODO: User signup workflow
    return '', 501


def change_password(password):
    return '', 501


def verify_email_address(verify):
    return '', 501


def send_reset_password_email(userId):
    return '', 501

