#!/bin/bash
set -e

# set local vars
BATS_TEST_DIRECTORY=$1
BATS_OUTPUT_DIRECTORY=$2

# install bats node packages
npm install

# run scan + write to results directory
mkdir -p ${BATS_OUTPUT_DIRECTORY}
./node_modules/bats/bin/bats --version
./node_modules/bats/bin/bats -r --formatter junit "${BATS_TEST_DIRECTORY}" | tee -a "${BATS_OUTPUT_DIRECTORY}/bats.junit.xml"
