#!/bin/bash

# Local JWT
#curl -c cookies -v http://localhost:5000/api/v1/authenticate -XPOST --header 'Content-Type: application/json' -d '{"auth":{"username":"demo","password":"123456"}}'

# Keycloak
curl -c cookies -v http://localhost:5000/api/v1/authenticate -XPOST --header 'Content-Type: application/json' -d '{"auth":{"username":"test","password":"mysamplepasswordissupersecure"}}'
