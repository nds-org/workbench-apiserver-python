import json
import logging

from jsonschema import validate

logger = logging.getLogger('pkg.types')

# Cache any schemas loaded from disk
schemas = {}


# TODO: Is manual validation needed?
# Generic validation function that loads schema from file
def validate_instance(instance, schema_type):
    # Check cache first
    if schema_type in schemas:
        schema = schemas[schema_type]   # Fetch from cache
        return validate(instance=instance, schema=schema)

    schema_path = './schemas/%s.json' % schema_type
    logger.debug('Validating instance with schema=%s' % schema_path)
    with open(schema_path) as json_file:
        schema = json.load(json_file)
        schemas[schema_type] = schema   # Cache this for later
        return validate(instance=instance, schema=schema)
