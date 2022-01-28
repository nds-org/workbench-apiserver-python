#!/bin/bash

curl -b cookies -c cookies -v -XGET 'http://localhost:5000/api/accounts/doesntmatter'
