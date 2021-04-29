account_schema = {
    "properties": {
        "created": {"type": "number"},
        "description": {"type": "string"},
        "email": {"type": "string"},
        "id": {"type": "string"},
        "inactiveTimeout": {"type": "number"},
        "lastLogin": {"type": "number"},
        "name": {"type": "string"},
        "namespace": {"type": "string"},
        "nexturl": {"type": "string"},
        "organization": {"type": "string"},
        "password": {"type": "string"},
        "status": {"type": "string"},
        "token": {"type": "string"}
    },
    "required": ["id", "email", "password"]
}
