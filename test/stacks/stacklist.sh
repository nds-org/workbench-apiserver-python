#!/bin/bash

curl -c cookies -b cookies -vvvv http://localhost:5000/api/v1/stacks --header 'Content-Type: application/json'
