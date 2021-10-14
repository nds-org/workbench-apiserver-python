#!/bin/bash

curl -c cookies -v http://localhost:5000/api/authenticate -XPOST --header 'Content-Type: application/json' -d '{"username":"test","password":"mysamplepasswordissupersecure"}'
