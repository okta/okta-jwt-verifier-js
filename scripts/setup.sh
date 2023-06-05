#!/bin/bash -xe

# Install required node version
export NVM_DIR="${HOME}/.nvm"
if ! setup_service node v14.18.2 &> /dev/null; then
  echo "Failed to install node"
  exit ${FAILED_SETUP}
fi

# Use the cacert bundled with centos as okta root CA is self-signed and cause issues downloading from yarn
if ! setup_service yarn 1.21.1 /etc/pki/tls/certs/ca-bundle.crt &> /dev/null; then
  echo "Failed to install yarn"
  exit ${FAILED_SETUP}
fi

cd ${OKTA_HOME}/${REPO}

# undo permissions change on scripts/publish.sh
git checkout -- scripts

# ensure we're in a branch on the correct sha
git checkout $BRANCH
git reset --hard $SHA

git config --global user.email "oktauploader@okta.com"
git config --global user.name "oktauploader-okta"

if ! yarn install ; then
  echo "yarn install failed! Exiting..."
  exit ${FAILED_SETUP}
fi
