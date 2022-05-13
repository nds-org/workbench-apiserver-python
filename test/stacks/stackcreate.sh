#!/bin/bash

curl -c cookies -b cookies -vvvv http://localhost:5000/api/v1/stacks -XPOST --header 'Content-Type: application/json' -d@./test/data/mongo.userapp.json
