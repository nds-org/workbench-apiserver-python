#!/bin/bash

if [ "$1" != "" ]; then
	curl -c cookies -b cookies -vvvv http://localhost:5000/api/v1/stacks/$1 -XPUT --header 'Content-Type: application/json' -d@./test/data/girder.stack.json
else
	echo "Usage: ./test/stacks/stackupdate.sh <id>"
fi
