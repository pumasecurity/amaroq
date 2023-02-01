#!/usr/bin/env bats

load '../node_modules/bats-support/load'
load '../node_modules/bats-assert/load'
load '../node_modules/bats-file/load'

@test "nessus-1-results" {
    assert_file_exist "$SCAN_DIRECTORY/10.3.1.112_1.sarif"
}


@test "nessus-1-new" {
    results=$(jq -r '.summary.new' $SCAN_DIRECTORY/summary_10.3.1.112_1.json)
    assert_equal "$results" "9"
}

@test "nessus-1-absent" {
    results=$(jq -r '.summary.absent' $SCAN_DIRECTORY/summary_10.3.1.112_1.json)
    assert_equal "$results" "0"
}

@test "nessus-1-unchanged" {
    results=$(jq -r '.summary.unchanged' $SCAN_DIRECTORY/summary_10.3.1.112_1.json)
    assert_equal "$results" "0"
}

@test "nessus-1-updated" {
    results=$(jq -r '.summary.updated' $SCAN_DIRECTORY/summary_10.3.1.112_1.json)
    assert_equal "$results" "0"
}

@test "nessus-1-suppressed" {
    results=$(jq -r '.summary.suppressed' $SCAN_DIRECTORY/summary_10.3.1.112_1.json)
    assert_equal "$results" "1"
}

@test "nessus-2-results" {
    assert_file_exist "$SCAN_DIRECTORY/10.3.1.112_2.sarif"
}

@test "nessus-2-new" {
    results=$(jq -r '.summary.new' $SCAN_DIRECTORY/summary_10.3.1.112_2.json)
    assert_equal "$results" "0"
}

@test "nessus-2-absent" {
    results=$(jq -r '.summary.absent' $SCAN_DIRECTORY/summary_10.3.1.112_2.json)
    assert_equal "$results" "9"
}

@test "nessus-2-unchanged" {
    results=$(jq -r '.summary.unchanged' $SCAN_DIRECTORY/summary_10.3.1.112_2.json)
    assert_equal "$results" "1"
}

@test "nessus-2-updated" {
    results=$(jq -r '.summary.updated' $SCAN_DIRECTORY/summary_10.3.1.112_2.json)
    assert_equal "$results" "0"
}

@test "nessus-2-suppressed" {
    results=$(jq -r '.summary.suppressed' $SCAN_DIRECTORY/summary_10.3.1.112_2.json)
    assert_equal "$results" "0"
}