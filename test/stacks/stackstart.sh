#!/bin/bash

if [ "$1" != "" ]; then
	curl -c cookies -b cookies -vvvv http://localhost:5000/api/v1/start/$1 -XGET --header 'Content-Type: application/json'
else
	echo "Usage: ./test/stacks/stackstart.sh <id>"
fi
