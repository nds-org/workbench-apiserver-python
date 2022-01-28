import connexion
import logging

from pkg.config import data_store

logger = logging.getLogger('api.v1.user_accounts')

def list_accounts():
    users = data_store.fetch_users()
    return users, 200


def create_account():
    return '', 501


def get_account_by_id(account_id):
    return '', 501


def update_account(account_id):
    return '', 501


def delete_account(account_id):
    return '', 501
