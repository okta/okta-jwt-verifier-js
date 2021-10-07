#!/bin/bash -xe

export ISSUER=https://foo.org

yarn lint
yarn test:unit
