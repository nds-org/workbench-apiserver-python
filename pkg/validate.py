from jsonschema import validate

from pkg import types

# TODO: for V2, use openapi2jsonschema
# TODO: for V1, use pyswagger?

def validate_account_info(account_info):
    return validate(instance=account_info, schema=types.account_schema)
