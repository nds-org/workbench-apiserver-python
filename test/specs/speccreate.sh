#!/bin/bash

FILENAME=${1:-./test/data/example4.spec.json}

curl -c cookies -b cookies -v http://localhost:5000/api/v1/services -XPOST --header 'Content-Type: application/json' -d@$FILENAME
