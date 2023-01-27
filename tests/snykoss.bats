#!/usr/bin/env bats

load '../node_modules/bats-support/load'
load '../node_modules/bats-assert/load'
load '../node_modules/bats-file/load'

@test "snykoss-1-results" {
    assert_file_exist "$SCAN_DIRECTORY/snyk-oss_1.sarif"
}

@test "snykoss-1-new" {
    results=$(jq -r '.summary.new' $SCAN_DIRECTORY/summary_snyk-oss_1.json)
    assert_equal "$results" "38"
}

@test "snykoss-1-suppressed" {
    results=$(jq -r '.summary.suppressed' $SCAN_DIRECTORY/summary_snyk-oss_1.json)
    assert_equal "$results" "3"
}

@test "snykoss-2-results" {
    assert_file_exist "$SCAN_DIRECTORY/snyk-oss_2.sarif"
}

@test "snykoss-2-new" {
    results=$(jq -r '.summary.new' $SCAN_DIRECTORY/summary_snyk-oss_2.json)
    assert_equal "$results" "1"
}

@test "snykoss-2-absent" {
    results=$(jq -r '.summary.absent' $SCAN_DIRECTORY/summary_snyk-oss_2.json)
    assert_equal "$results" "5"
}

@test "snykoss-2-unchanged" {
    results=$(jq -r '.summary.unchanged' $SCAN_DIRECTORY/summary_snyk-oss_2.json)
    assert_equal "$results" "32"
}

@test "snykoss-2-suppressed" {
    results=$(jq -r '.summary.suppressed' $SCAN_DIRECTORY/summary_snyk-oss_2.json)
    assert_equal "$results" "4"
}

@test "snykoss-2-date-filter" {
    run bash -c "docker run -v ${SCAN_DIRECTORY}:/scan-output pumasecurity/amaroq:${VERSION} sarif query --return-count -e \"rule.properties.security-severity > 7.0 && properties.packageManager == 'nuget' && properties.vulnPublicationDate > '2022-04-01' && properties.vulnPublicationDate < '2022-04-30'\" /scan-output/snyk-oss_2.sarif"
    assert_failure 5
}
