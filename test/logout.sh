#!/bin/bash

curl -b cookies -c cookies -v -XDELETE 'http://localhost:5000/api/authenticate'
