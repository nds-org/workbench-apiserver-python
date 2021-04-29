from jsonschema import validate

from pkg import types


def validate_account_info(account_info):
    return validate(instance=account_info, schema=types.account_schema)
