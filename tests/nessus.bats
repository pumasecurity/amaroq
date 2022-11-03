#!/usr/bin/env bats

load '../node_modules/bats-support/load'
load '../node_modules/bats-assert/load'
load '../node_modules/bats-file/load'

@test "nessus-1-results" {
    assert_file_exist "$SCAN_DIRECTORY/10.3.1.112_1.sarif"
}
