# Amaroq Vulnerability Orchestration and Correlation Engine

The Amaroq Engine performs vulnerability analysis, suppression, and threshold enforcement for multiple security tools. Unique instance identifiers (fingerprints) are added to each vulnerability, and then matched with the previous vulnerability results (if available). Custom suppression rules are applied to the vulnerability results, which results in a final set of vulnerabilities to analyze. The final set of vulnerabilities are queried against a series of expressions to determine if any valid findings should trigger a failure or notification in the pipeline.

## Installation

Amaroq runs inside an Alpine container image with the dependencies required for the SARIF SDK (C#) and Python scripts to execute. The [Dockerfile](./../Dockerfile) builds the custom [SARIF SDK](https://github.com/pumasecurity/sarif-sdk), copies the binary into the runtime image, and adds other required libraries.

Start by cloning the repository and required sub-modules:

```bash
git clone --recursive https://github.com/pumasecurity/amaroq.git
```

To update the sub-modules after the initial clone, the following command will pull the latest commit from the `release` branch.

```bash
git submodule set-branch --branch release sarif-sdk
git submodule update --remote
git submodule status
```

Then, build the container image by running the following command:

```bash
docker build --network host --build-arg VERSION=0.4 -t pumasecurity/amaroq:latest .
```

## Running ASOC Analysis

To run an analysis, run the container image mounting directories containing the "input" file(s) and "output" location. The following example shows how to run an Amaroq analysis for the initial analysis of a Puma Scan SAST scan.

```bash
docker run -v ${PWD}/docs/samples/pumascan:/scan-input -v ${PWD}/docs/samples/pumascan:/scan-output pumasecurity/amaroq:latest amaroq.py --tool PumaScan --current /scan-input/pumascan_1.sarif --output-directory /scan-output --output-filename pumascan_results_1.sarif
```

The output will confirm the Puma Scan schema was converted to a SARIF results format (if necessary) and the differential analysis was performed against the results.

```bash

```

On subsequent executions, pass the previous results file into the `amaroq.py` script using the `--previous` argument. The results will be merged and analyzed using the differential analysis capability.

```bash
docker run -v ${PWD}/docs/samples/cis/input:/scan-input -v ${PWD}/docs/samples/cis/output:/scan-output pumasecurity/amaroq:latest amaroq.py --tool CisCat --previous /scan-input/cis_results_1.sarif --current /scan-input/cis_scan_2.json --settings /scan-input/settings_2.json --output-directory /scan-output --output-filename cis_results_2.sarif
```

## Settings Configuration

To run the ASOC Analysis, the container must be passed a configuration file (e.g. settings.json) that defines each supported tool's suppression rules and threshold queries. The following settings schema is supported:

```json
{
  //future placeholder for backwards compatible schema changes 
  "version": "1.0.0",
  //defines an array of configuration settings for each tool (one element per tool is expected)
  "settings": [
    {
      //defines which tool the configuration will apply
      "tool": "Nessus|CisCat|ShiftLeft|SnykCode|SnykOpenSource",
      //future placeholder for backwards compatible schema changes
      "version": "1.0.0",
      //defines an array of suppression rules to apply to the output file (default empty array)
      "suppressions": [
        {
          //Required: Defines an expression for the suppression search (use empty string for default value)
          "expression": "",
          //Required: defines an alias for each suppression
          "alias": "eric.johnson",
          //Required: defines the status for each suppression (Accepted|UnderReview|Rejected)
          "status": "Accepted",
           //Required: defines a description (justification) for each suppression
          "justification": "False positive",
          //Required: Defines an expiration date for each suppression (use empty string for default value)
          "expiryUtc": "2022-10-30 00:00:00",
          //Required: List of result guids to suppress (use empty array for default value)
          "results-guids": [
            "90198fc8-83f5-45a0-bc20-b6e23cbe0ffc"
          ]
        },
      ],
      //defines an array of threshold expressions to evaluate before returning from the asoc process. 
      //The container's exit code will contain the value from any expression resulting in a match value greater than 0
      "thresholds": [
        "IsSuppressed == false && Rank > 9.0"
      ]
    }
}
```

The `settings.json` file is parsed by `jq` in the `amaroq.py` script. `jq` is a fairly strict JSON parser that will fail if the last element in an array or object has a comma. To verify that the `settings.json` file is parsable, run the following command:

```bash
cat settings.json | jq
```

## Data Transformation

### Phase 1: Data Transformation

Scan results files located in the `/scan-input` directory will be transformed from their native format (.nessus.xml, shiftleft.json, etc.) into the common SARIF schema.

#### CIS CAT

Conversion support for CIS CAT results has been built into the SARIF SDK Multitool. The `amaroq.py` script will automatically convert the `CisCat` results to a SARIF format before processing using the following command:

```bash
sarif convert --tool CisCat --output ./cis_scan_example.sarif ./cis_scan_example.json
```

#### Shift Left

Conversion support for Shift Left results is currently managed by the forked [joern2sarif](https://github.com/pumasecurity/joern2sarif) library.  The [Dockerfile](./Dockerfile) installs the required libraries and builds the custom [joern2sarif](https://github.com/pumasecurity/joern2sarif) package.

The `amaroq.py` script will automatically convert the `ShiftLeft` results to a SARIF format before processing using the following command:

```bash
joern2sarif -i ./shiftleft-sample-findings.json -o ./shiftleft-raw-v1.sarif
```

#### Nessus XML

Conversion support for Nessus results has been built into the SARIF SDK Multitool. The `amaroq.py` script will automatically convert the `Nessus` results to a SARIF format before processing using the following command:

```bash
sarif convert --tool Nessus --output ./sample-tenable-scan-result_1.sarif ./sample-tenable-scan-result_1.nessus
```

#### Snyk Code

Snyk supports the SARIF format out of the box using the `--sarif` switch. Sample files can be found in the [Snyk Code Samples](./docs/samples/snyk-code/input) directory. However, the SARIF format produced by Snyk is missing a few required fields for downstream matching and suppression. The `amaroq.py` script automatically transforms the Synk Code SARIF output into a valid SARIF document using the following command:

```bash
sarif --tool GenericSarif convert ./docs/samples/snyk-code/input/snyk-raw_1.sarif --output ./docs/samples/snyk-code/input/snyk-converted_1.sarif
```

#### Snyk Open Source

Snyk Open Source supports the SARIF format out of the box using the `--sarif` switch; however the data is not populated sufficiently. Current known issues with the Snyk CLI include:

- Vulnerabilities (results) seem to be missing from the dataset. See the JSON versus the SARIF in the [Snyk Open Source Samples](./docs/samples/snyk-open-source/input) directory.

- Fingerprints for match forward are not populated into each result

- Rank is not populated with the CVSS score

- Metadata such as package manager, name, and version are not added to the properties. CVSS vector string is not populated into the properties.

- Tag values for GH Advanced Security are not populated into each rule.

This information has been communicated to the Snyk team for review. Conversion support has been built into the SARIF SDK until Snyk is able to make these corrections. The `amaroq.py` script will automatically convert the `SnykOpenSource` results to a SARIF format before processing using the following command:

```bash
sarif convert --tool SnykOpenSource --output ./docs/samples/snyk-open-source/input/snyk-oss-cli_1.sarif ./docs/samples/snyk-open-source/input/snyk-oss-cli_1.json
```

### Phase 2: SARIF SDK Multitool Workflow

The [SARIF SDK](https://github.com/microsoft/sarif-sdk) provides capabilities for managing SARIF vulnerability results over time. The SDK has been forked to [pumasecurity/sarif-sdk](https://github.com/pumasecurity/sarif-sdk/tree/main) to ensure we have control over the functionality, missing features, and edge cases.

#### Match Results

From the common SARIF format, the `amaroq.py` script will run the `match-results-forward` command to generate a match results file for each scanner that will contain instance and correlation identifiers:

```bash
sarif match-results-forward --output-file-path ./cis_results.sarif ./cis_scan.sarif
```

Each result will have the following attributes added:

```json
"guid": "fcc0bf8e-65b3-4039-aba3-fcec5868d4df",
"correlationGuid": "fcc0bf8e-65b3-4039-aba3-fcec5868d4df",
...
"baselineState": "new",
"provenance": {
    "firstDetectionTimeUtc": "2022-07-27T19:36:45.819Z"
},
```

On subsequent runs, previous and current SARIF files will be matched before differential analysis. The `amaroq.py` script will match the new scan results with the old results file:

```bash
sarif match-results-forward --previous ./cis_results_1.sarif --output-file-path ./cis_results_2.sarif ./cis_scan_2.sarif
```

#### Threshold Queries

With the instance identifiers and correlation results, we can query the results file for threshold enforcement. The `--return-count` argument will return the number of matches for the given expression. For example, the following command will search for all non-suppressed results with a **BaselineState** value of **New** (i.e. New Results):

```bash
sarif query --expression "IsSuppressed == false && BaselineState == 'New'" --return-count ./cis_results_2.sarif
```

The exit code can be found using the `$?` shell command.

```bash
Found 1 of 11 results matched in 0.3s.
echo $?
1
```

More advanced expressions can be used with `and`, `or` and `count` arguments. See [SARIF SDK Query Mode](./sarif-sdk/docs/query-mode.md) for the full list of supported fields and query syntax examples. Here are a few common examples:

* Query for Absent Results that have been removed in the current scan:

```bash
sarif query --return-count --expression "BaselineState == 'Absent'"
```

* Query for Suppressed results that are false positives for have been hidden from the viewer:

```bash
sarif query --return-count --expression "IsSuppressed == true && BaselineState != 'Absent'" $sarifResults
```

* Query for non-suppressed results with an updated status:

```bash
sarif query --return-count --expression "IsSuppressed == false && BaselineState == 'Updated'" $sarifResults
```

* Query for non-suppressed results with an unchanged status:

```bash
sarif query --return-count --expression "IsSuppressed == false && BaselineState == 'Unchanged'" $sarifResults
```

* Query for non-suppressed results for a given rule id:

```bash
sarif query --return-count --expression "IsSuppressed == false && RuleId == 'xccdf_org.cisecurity.benchmarks_rule_1.1.1.1_Ensure_mounting_of_cramfs_filesystems_is_disabled'" $sarifResults
```

* Query for critical risk results by the rank:

```bash
sarif query --return-count --expression "IsSuppressed == false && Rank > 9.0" $sarifResults
```

* Question for critical risk results with a vulnerability publication date within the last 14 days:

```bash
sarif query --return-count --expression "IsSuppressed == false && Rank > 9.0 && properties.vulnPublicationDate > '$(date +"%Y-%m-%dT%H:%M:%S" -date '-14 days')'" $sarifResults
```

#### Suppressing False Positives

Suppressions can be added directly to the SARIF results by adding a suppression object to one to many results. The following command will add a suppression to every result in the file:

```bash
docker run -v ${PWD}:/results pumasecurity/amaroq:latest sarif suppress -i --guids --timestamps --alias "eric.johnson" --status "Accepted" --justification "False positive" /results/snyk-results.sarif
```

Rather than suppressing all results, specific rules or a groups of results can be suppressed using the `--expression` argument. For example, to suppress an entire `ruleid` (e.g., category), use the `--expression` argument to query for results to suppress:

```bash
docker run -v ${PWD}:/results pumasecurity/amaroq:latest sarif suppress -i --expression "ruleId == 'csharp/InsecureCipher'" --guids --timestamps --alias "eric.johnson" --status "Accepted" --justification "False positive" /results/snyk-results.sarif
```

To suppress an individual result by `guid`, use the `--expression` argument to query for the `guid` to suppress:

```bash
docker run -v ${PWD}:/results pumasecurity/amaroq:latest sarif suppress -i --expression "guid == 'd87f01b1-ef41-4068-a848-d1ac7a466c07'" --guids --timestamps --alias "eric.johnson" --status "Accepted" --justification "False positive" /results/snyk-results.sarif
```

To suppress multiple instances using their results `guid`, you can pass a comma delimited list of guids to the `--results-guids` argument:

```bash
docker run -v ${PWD}:/results pumasecurity/amaroq:latest sarif suppress -i --results-guids "ec03620c-0b4a-44ff-be97-7162d4a9bfcd,efc126a6-08df-4ed8-ab06-1d8f5e99752d" --guids --timestamps --alias "eric.johnson" --status "Accepted" --justification "False positive" /results/snyk-results.sarif
```

## Output Files

The `amaroq.py` script will generate up to 3 different files in the `--output-directory`. The basename will be from the `--output-file` switch.

* **New Baseline File**: The final SARIF result file from the data transformation, match results (if a previous file is supplied), and suppression rules will be written to the `${output-directory}/${output-file}.sarif` location.

* **Console Output Log**: Each run will produce a console output log file in the `${output-directory}/process-sarif-${Tool}-$(date +"%Y%m%d%H%M%S").log` location.

* **New Baseline Summary**: The final SARIF result file from the data transformation, match results, and suppression rules will be summarized in the `${output-directory}/summary_${output-file}.json` location. The schema for this summary file is:

```json
{
  "version": "1.0.0",
  "summary": {
    "new": 0,
    "absent": 0,
    "unchanged": 0,
    "updated": 0,
    "suppressed": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
  }
}
```

* **Active Output File**: Supplying the `--active-only` argument will create an output file called `${output-directory}/active_${output-file}.sarif` in the output directory. The active file will not include any suppressed results. This is only necessary when downstream file processing is done by a CI / CD extension that does not honor the SARIF suppression data.

## Troubleshooting

TBD

## Miscellaneous Notes

### SARIF Tools

[sarif-tools](https://github.com/microsoft/sarif-tools) is an alternate, less featured and less maintained, SARIF command line tool written in Python. Research and comparison found this option to be unreliable performing differential operations. Especially in complex SAST scenarios where line numbers were changing inside a given file. The following example shows a diff using the `sarif-tool` against test data:

```bash
sarif diff --output ./snyk-results-v2.diff ./snyk-results.sarif ./snyk-results-v2.sarif
```

Output does not show the absent findings being removed:

```bash
error level: +0 -0 no changes
warning level: +0 +0
  Number of occurrences 1 -> 2 (+1) for issue "csharp/RequestValidationDisabled (BETA Suggestion) The ValidateInput attribute is set to False. Request Validation is generally desirable and should be left enabled as a defense in depth measure to prevent XSS attacks."
note level: +0 -0 no changes
all levels: +0 +0
```
