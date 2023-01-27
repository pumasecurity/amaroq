#!/usr/bin/env bats

load '../node_modules/bats-support/load'
load '../node_modules/bats-assert/load'
load '../node_modules/bats-file/load'

@test "snykcode-1-results" {
    assert_file_exist "$SCAN_DIRECTORY/snyk-v1.sarif"
}

@test "snykcode-1-new" {
    results=$(jq -r '.summary.new' $SCAN_DIRECTORY/summary_snyk-v1.json)
    assert_equal "$results" "6"
}

@test "snykcode-1-suppressed" {
    results=$(jq -r '.summary.suppressed' $SCAN_DIRECTORY/summary_snyk-v1.json)
    assert_equal "$results" "4"
}

@test "snykcode-2-results" {
    assert_file_exist "$SCAN_DIRECTORY/snyk-v2.sarif"
}

@test "snykcode-2-new" {
    results=$(jq -r '.summary.new' $SCAN_DIRECTORY/summary_snyk-v2.json)
    assert_equal "$results" "1"
}

@test "snykcode-2-absent" {
    results=$(jq -r '.summary.absent' $SCAN_DIRECTORY/summary_snyk-v2.json)
    assert_equal "$results" "3"
}

@test "snykcode-2-unchanged" {
    results=$(jq -r '.summary.unchanged' $SCAN_DIRECTORY/summary_snyk-v2.json)
    assert_equal "$results" "3"
}

@test "snykcode-2-updated" {
    results=$(jq -r '.summary.updated' $SCAN_DIRECTORY/summary_snyk-v2.json)
    assert_equal "$results" "1"
}

@test "snykcode-2-suppressed" {
    results=$(jq -r '.summary.suppressed' $SCAN_DIRECTORY/summary_snyk-v2.json)
    assert_equal "$results" "3"
}

@test "snykcode-2-date-filter" {
    run bash -c "docker run -v ${SCAN_DIRECTORY}:/scan-output pumasecurity/amaroq:${VERSION} sarif query --return-count -e \"properties.priorityScore = 301\" /scan-output/snyk-v2.sarif"
    assert_failure 3
}
