#!/bin/bash

curl -c cookies -b cookies -v http://localhost:5000/api/v1/services/example4 -XGET
