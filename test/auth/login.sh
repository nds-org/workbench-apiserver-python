#!/bin/bash

# Local JWT
#curl -c cookies -v http://localhost:5000/api/v1/authenticate -XPOST --header 'Content-Type: application/json' -d '{"username":"demo","password":"123456"}'

# Keycloak
curl -c cookies -v http://localhost:5000/api/v1/authenticate -XPOST --header 'Content-Type: application/json' -d '{"username":"test","password":"123456"}'
