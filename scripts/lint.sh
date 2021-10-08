#!/bin/bash -xe

source ${OKTA_HOME}/${REPO}/scripts/setup.sh

if ! yarn lint; then
  echo "lint failed! Exiting..."
  exit ${TEST_FAILURE}
fi

exit ${SUCCESS}
