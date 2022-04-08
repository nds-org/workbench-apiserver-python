#!/bin/bash

curl -c cookies -b cookies -v http://localhost:5000/api/v1/stacks -XPOST --header 'Content-Type: application/json' -d@./test/data/girder.stack.json
