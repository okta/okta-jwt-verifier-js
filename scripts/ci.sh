#!/bin/bash -x

source ${OKTA_HOME}/${REPO}/scripts/setup.sh

export TEST_SUITE_TYPE="junit"
export TEST_RESULT_FILE_DIR="${REPO}/reports/ci"

export ISSUER=https://sdk-test-ok14.okta.com/oauth2/default
export CLIENT_ID=0oa5dztAOmaWJ09Dm694
export USERNAME=ci.user@test.com
get_terminus_secret "/" ci_password PASSWORD

export CI=true
export DBUS_SESSION_BUS_ADDRESS=/dev/null

# Run the tests
if ! yarn test:ci; then
  echo "ci tests failed! Exiting..."
  exit ${TEST_FAILURE}
fi

echo ${TEST_SUITE_TYPE} > ${TEST_SUITE_TYPE_FILE}
echo ${TEST_RESULT_FILE_DIR} > ${TEST_RESULT_FILE_DIR_FILE}
exit ${PUBLISH_TYPE_AND_RESULT_DIR}
