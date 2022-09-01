#!/bin/bash

if [ "${GIT_REPO}" != "" ]; then
  git clone ${GIT_REPO} -b ${GIT_BRANCH} ${TARGET_FOLDER}
fi

python loadspecs.py ${TARGET_FOLDER}
