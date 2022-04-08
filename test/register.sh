#!/bin/bash

curl -c cookies -v http://localhost:5000/api/v1/accounts -XPOST --header 'Content-Type: application/json' -d '{"username":"demo","password":"123456","email":"demo@fakeemail.org","name":"Demo User"}'
