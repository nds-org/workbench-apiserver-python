#!/bin/bash

if [ "${GIT_REPO}" != "" ]; then
  if [ "${GIT_BRANCH}" != "" ]; then
    git clone ${GIT_REPO} -b ${GIT_BRANCH} ${TARGET_FOLDER}
  elif
    git clone ${GIT_REPO} ${TARGET_FOLDER}
  fi
fi

python loadspecs.py ${TARGET_FOLDER}
