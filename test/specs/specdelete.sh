#!/bin/bash

if [ "$1" != "" ]; then
	curl -c cookies -b cookies -v http://localhost:5000/api/v1/services/$1 -XDELETE
else
        echo "Usage: ./test/specs/specdelete.sh <id>"
fi

