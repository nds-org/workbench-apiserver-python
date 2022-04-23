#!/bin/bash

if [ "$1" != "" ]; then
	curl -c cookies -b cookies -vvvv http://localhost:5000/api/v1/stacks/$1 -XDELETE --header 'Content-Type: application/json'
else
	echo "Usage: ./test/stacks/stackdelete.sh <id>"
fi
