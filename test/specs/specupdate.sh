#!/bin/bash

curl -c cookies -b cookies -v http://localhost:5000/api/v1/services/example4 -XPUT --header 'Content-Type: application/json' -d@./test/data/mongo.spec.json
