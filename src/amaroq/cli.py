#!/usr/bin/env python3

import argparse
import datetime
import json
import logging
import os
import subprocess
import logging
import yaml
import jsonschema
from asyncio.log import logger
from importlib import metadata
from re import A
from shlex import split
from subprocess import DEVNULL, PIPE, STDOUT, Popen
from tabnanny import check
from typing import Iterable
from .settingsValidator import validateSettings

# debug mode: set AMAROQ_SARIF_COMMAND (e.g. `dotnet /source/sarif-sdk/bld/bin/AnyCPU_Debug/Sarif.Multitool/netcoreapp3.1/Sarif.Multitool.dll`)
if os.environ.get("AMAROQ_SARIF_COMMAND"):
    sarif = os.environ.get("AMAROQ_SARIF_COMMAND")
else:
    sarif = "sarif"

# read version from package data
version = metadata.version('amaroq')

# default verbose value
verbose = 0

# json schemas
summaryResultsSchema = "1.0"

# supported tool conversions
supportedTools: Iterable[str] = ["GenericSarif", "SnykOpenSource", "Nessus"]
       
def execute_cmd_not_visible(cmd):
    try:
        logging.debug("Executing command: \"{}\"".format(cmd))
        out = subprocess.run(cmd, shell=True, universal_newlines=True,
                             check=False, capture_output=False, stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError as err:
        logging.error("Aborting: Error executing \"{}\"".format(cmd))
        logging.error("Details: {}".format(err))
        logging.error("Details: {}".format(err.output))
        exit(1)
    return out.returncode


def execute_command(cmd, stdout=PIPE):
    try:
        logging.debug("Executing command: \"{}\"".format(cmd))
        process = Popen(split(cmd), stdout=stdout,
                        stderr=STDOUT, encoding='utf8')

        while True:
            output = process.stdout.readline()
            if len(output) == 0 and process.poll() is not None:
                break
            if output:
                logging.info(output.strip())
        rc = process.poll()
        return rc
    except KeyboardInterrupt:
        # process.terminate()
        exit()
    except Exception as ex:
        logging.error("Encountered an error: ", ex)


def execute_command_with_output(cmd):
    try:
        logging.debug("Executing command: \"{}\"".format(cmd))
        rc = subprocess.run(cmd, encoding='utf8',
                            shell=True, universal_newlines=True)
        return rc
    except KeyboardInterrupt:
        # process.terminate()
        exit()
    except Exception as ex:
        logging.error("Encountered an error: ", ex)

def apply_suppression_sarif_log(sarifResults:str, alias:str, expression: str, status: str, justification: str, expiryUtc: str, resultsGuids):
    cmd = '{sarif} suppress "{sarifInput}" -i --timestamps --alias "{alias}" --status "{status}" --justification "{justification}"'.format(
        sarif=sarif, sarifInput=sarifResults, alias=alias, status=status, justification=justification)    
    if expiryUtc :
        cmd = cmd + ' --expiryUtc "{expiryUtc}"'.format(expiryUtc=expiryUtc)
    if resultsGuids:
        cmd = cmd + ' --results-guids "{guids}"'.format(guids=",".join("{0}".format(r) for r in resultsGuids))
    if expression:
        cmd = cmd + ' --expression "{expression}"'.format(expression=expression)
    # run sarif suppress command
    _rc = execute_command(cmd)
    if _rc > 0:
        raise Exception("Failure to Suppress")

def suppress_sarif_log(sarifResults:str, targetTool: str, settingsFile:str):
    settingsData = None
    with open(settingsFile, "r") as stream:
        try:
            settingsData = yaml.safe_load(stream)            
        except yaml.YAMLError as exc:
            logging.error("Error loading settings:")
            if hasattr(exc, 'problem_mark'):
                mark = exc.problem_mark
                logging.error("Error position: (%s:%s)" % (mark.line+1, mark.column+1))
            else:
                logging.error(exc)
    if not settingsData:
        logging.error("Suppressions not applied. Exiting with Error")
        exit(1) # TODO add error code??
    settings = settingsData['settings']
    for toolsettings in settings:
        tool = toolsettings.get('tool', None)
        suppressions = toolsettings.get('suppressions', None)               
        if tool and tool == targetTool:
            logging.info("\tApplying {suppressionCount} suppression rule(s).".format(suppressionCount=len(suppressions)))
            if suppressions:
                for suppression in suppressions:
                    expression = suppression.get('expression', "")
                    alias = suppression.get('alias')
                    status = suppression.get('status')
                    justification = suppression.get('justification')
                    expiryUtc = suppression.get('expiryUtc', None)
                    resultsGuids = suppression.get('results-guids', [])

                    if not alias and not status and not justification:
                        logging.error("One or more required supression parameters are empty: \nAlais: {alais}\nSTATUS: {status}\nJUSTIFICATION: {justification}".format(alias=alias, status=status, justification=justification))    
                        exit(1)

                    #suppress only value expiry dates or if date is not given
                    suppress = (expiryUtc and datetime.datetime.utcnow() < expiryUtc) or (not expiryUtc)
                    if suppress:
                        apply_suppression_sarif_log(sarifResults=sarifResults, expression=expression, alias=alias, status=status, justification=justification, resultsGuids=resultsGuids, expiryUtc=expiryUtc)                


def apply_amaroq_metadata(sarifResults: str, organizationId: str, projectId: str):
    logging.info("\tGenerating Amaroq metadata...")
    # read sarif log
    with open(sarifResults) as f:
        sarifResultsData = json.load(f)

    runs = sarifResultsData['runs']
    for run in runs:        

        runtimestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        tool = run['tool']['driver']['name']
        unchanged = 0
        new = 0
        updated = 0
        absent = 0        
        suppressed = 0

        critical = 0
        high = 0
        medium = 0
        low = 0
        for result in run["results"]:            
            #TODO suppressed logic
            # // If the status of any of the suppressions is "underReview" or "rejected",
            # // then the result should not be considered suppressed. Otherwise, the result should be considered suppressed.
            # // https://github.com/microsoft/sarif-tutorials/blob/main/docs/Displaying-results-in-a-viewer.md#determining-suppression-status           
            # isSuppressed = !suppressions.Any(s => s.Status == SuppressionStatus.UnderReview || s.Status == SuppressionStatus.Rejected);

            # // if we have suppressions, check expiration
            # if (isSuppressed && checkExpired)
            # {
            #     isSuppressed = suppressions.Any(s => (!s.TryGetProperty("expiryUtc", out DateTime noExpiryUtc) || (s.TryGetProperty("expiryUtc", out DateTime expiryUtc) && expiryUtc > DateTime.UtcNow)) && s.Status == SuppressionStatus.Accepted);
            # }

            suppressedValue = False
            baselineState = result["baselineState"]
                
            if suppressedValue and baselineState != "Absent":
                suppressed+=1
            
            if not suppressedValue:                
                if baselineState == "unchanged":
                    unchanged+=1                         
                if baselineState == "new":
                    new+=1
                if baselineState == "updated":
                    updated+=1
                if baselineState == "absent":
                    absent+=1                
                
                #TODO vuln level logic            
                rank = result.get('rank')
                if rank:
                    if baselineState != "absent":
                        if rank >= 9.0:
                            critical+=1
                        if rank >= 7.0 and rank < 9.0:
                            high+=1
                        if rank >= 4.0 and rank < 7.0:
                            medium+=1
                        if rank > 0 and rank < 4.0:
                            low+=1

        amaroq = {
            "timestamp": runtimestamp,
            "version": summaryResultsSchema,
            "summary": {
                "new": new,
                "absent": absent,
                "unchanged": unchanged,
                "updated": updated,
                "suppressed": suppressed,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low                
            },
            "organizationId": organizationId.upper(),
            "projectId": projectId.upper(),     
            "id": "amaroq-{tool}-{timestamp}".format(tool=tool, timestamp=runtimestamp)     
        }

        properties = run.get('properties', None)
        if properties:
            run['properties']['amaroq'] = amaroq                    
        else:
           run['properties'] = {
                "amaroq": amaroq
            }

    logging.info("\tUpdating sarif log with amaroq metadata to file...")
    # update sarif log with new metadata
    with open(sarifResults, "w") as write_file:
            json.dump(sarifResultsData, write_file)

def convert_sarif_log(resultInput: str, sarifOutput: str, targetTool: str):
    logging.info("\tConverting " + targetTool + " results from " +
                 resultInput + " to " + sarifOutput + ".")

    # run sarif convert command
    cmd = "{sarif} convert {resultInput} --output {sarifOutput} --tool {targetTool}".format(
        sarif=sarif, resultInput=resultInput, sarifOutput=sarifOutput, targetTool=targetTool)

    _rc = execute_command(cmd)
    if _rc > 0:
        raise Exception("Failure to Convert")


def diff_sarif_log(current: str, fileOutput: str, baseline: str):
    logging.info("\tCurrent results: " + current)
    logging.info("\tOutput results: " + fileOutput)

    # Match results, ignoring baseline if not requested. (First run of tool)
    cmd = ""
    if not baseline:
        cmd = "{sarif} match-results-forward --output-file-path {fileOutput} {current}".format(
            sarif=sarif, baseline=baseline, fileOutput=fileOutput, current=current)
    else:
        logging.info("\tBaseline results: " + baseline)
        cmd = "{sarif} match-results-forward --previous {baseline} --output-file-path {fileOutput} {current}".format(
            sarif=sarif, baseline=baseline, fileOutput=fileOutput, current=current)
    _rc = execute_command(cmd)
    if _rc > 0:
        raise Exception("Failed", "match-results-forward")


def summary_sarif_log(organizationId: str, projectId:str, targetTool: str, sarifResults: str, summaryResults: str,  activeResults: str, runtimestamp: str):
    logging.info("\tGenerating results summary...")

    logging.debug("Querying new instances..")
    cmd = '{sarif} query --return-count --expression {expression} {sarifResults}'.format(
        sarif=sarif, sarifResults=sarifResults, expression='"IsSuppressed == false && BaselineState == \'New\'"')
    new_results = execute_cmd_not_visible(cmd)

    logging.debug("Querying absent instances..")
    cmd = '{sarif} query --return-count --expression {expression} {sarifResults}'.format(
        sarif=sarif, sarifResults=sarifResults, expression='"BaselineState == \'Absent\'"')
    absent_results = execute_cmd_not_visible(cmd)

    logging.debug("Querying unchanged instances..")
    cmd = '{sarif} query --return-count --expression {expression} {sarifResults}'.format(
        sarif=sarif, sarifResults=sarifResults, expression='"IsSuppressed == false && BaselineState == \'Unchanged\'"')
    unchanged_results = execute_cmd_not_visible(cmd)

    logging.debug("Querying updated instances..")
    cmd = '{sarif} query --return-count --expression {expression} {sarifResults}'.format(
        sarif=sarif, sarifResults=sarifResults, expression='"IsSuppressed == false && BaselineState == \'Updated\'"')
    updated_results = execute_cmd_not_visible(cmd)

    logging.debug("Querying suppressed instances..")
    cmd = '{sarif} query --return-count --expression {expression} {sarifResults}'.format(
        sarif=sarif, sarifResults=sarifResults, expression='"IsSuppressed == true && BaselineState != \'Absent\'"')
    suppressed_results = execute_cmd_not_visible(cmd)

    logging.debug("Querying critical instances..")
    cmd = '{sarif} query --return-count --expression {expression} {sarifResults}'.format(
        sarif=sarif, sarifResults=sarifResults, expression='"IsSuppressed == false && BaselineState != \'Absent\' && Rank >= 9.0"')
    critical_results = execute_cmd_not_visible(cmd)

    logging.debug("Querying high instances..")
    cmd = '{sarif} query --return-count --expression {expression} {sarifResults}'.format(
        sarif=sarif, sarifResults=sarifResults, expression='"IsSuppressed == false && BaselineState != \'Absent\' && Rank >= 7.0 && Rank < 9.0"')
    high_results = execute_cmd_not_visible(cmd)

    logging.debug("Querying medium instances..")
    cmd = '{sarif} query --return-count --expression {expression} {sarifResults}'.format(
        sarif=sarif, sarifResults=sarifResults, expression='"IsSuppressed == false && BaselineState != \'Absent\' && Rank >= 4.0 && Rank < 7.0"')
    medium_results = execute_cmd_not_visible(cmd)

    logging.debug("Querying low instances..")
    cmd = '{sarif} query --return-count --expression {expression} {sarifResults}'.format(
        sarif=sarif, sarifResults=sarifResults, expression='"IsSuppressed == false && BaselineState != \'Absent\' && Rank > 0 && Rank < 4.0"')
    low_results = execute_cmd_not_visible(cmd)

    results = """\tSummary:
\tNew Results:\t\t{new_results}
\tAbsent Results:\t\t{absent_results}
\tUnchanged Results:\t{unchanged_results}
\tUpdated Results:\t{updated_results}
\tSuppressed Results:\t{suppressed_results}

\tCritical Results:\t{critical_results}
\tHigh Results:\t\t{high_results}
\tMedium Results:\t\t{medium_results}
\tLow Results:\t\t{low_results}
    """.format(new_results=new_results, absent_results=absent_results, unchanged_results=unchanged_results, updated_results=updated_results,
               suppressed_results=suppressed_results, critical_results=critical_results, high_results=high_results, medium_results=medium_results, low_results=low_results)
    logging.info(results)

    # write summary data to disk
    if summaryResults:
        logging.info(
            "\tWriting summary results to: \"{}\"".format(summaryResults))
        summary = {
            "timestamp": runtimestamp,
            "version": summaryResultsSchema,
            "summary": {
                "new": new_results,
                "absent": absent_results,
                "unchanged": unchanged_results,
                "updated": updated_results,
                "suppressed": suppressed_results,
                "critical": critical_results,
                "high": high_results,
                "medium": medium_results,
                "low": low_results
            },
          "organizationId": organizationId,
          "projectId": projectId,     
          "id": "amaroq-{tool}-{timestamp}".format(tool=targetTool, timestamp=runtimestamp)     
        }

        with open(summaryResults, "w") as write_file:
            json.dump(summary, write_file)

    # Write trimmed results file (for display in CI / CD)
    if activeResults:
        logging.info("Writing active results to: \"{}\"".format(
            activeResults))
        cmd = '{sarif} query --expression {expression} --output {activeResults} {sarifResults}'.format(
            sarif=sarif, sarifResults=sarifResults, expression='"IsSuppressed == false && BaselineState != \'Absent\'"', activeResults=activeResults)
        rc = execute_cmd_not_visible(cmd)
        logger.info("Total Active Findings: {}".format(rc))


def print_art():
    logging.info("""
    ___
   /   |  ____ ___  ____ __________  ____ _
  / /| | / __ `__ \/ __ `/ ___/ __ \/ __ `/
 / ___ |/ / / / / / /_/ / /  / /_/ / /_/ /
/_/  |_/_/ /_/ /_/\__,_/_/   \____/\__, /
                                     /_/
    """)
    print_version()


def print_version():
    try:
        logging.info("Version {version}".format(version=version))
        result = execute_command(
            "{sarif} --version".format(sarif=sarif))
        logging.info("")

        if result != 0:
            raise Exception("Sarif SDK version check failed")
    except FileNotFoundError as f:
        raise Exception("Sarif SDK was not found")


def build_args():
    parser = argparse.ArgumentParser(prog='amaroq')

    parser.add_argument("-v", "--verbose", action='count', default=0,
                        help="verbosity level (default: %(default)s)")

    parser.add_argument("--version", action="store_true",
                        help="Show amaroq version number and exit")

    required = parser.add_argument_group('required')
    required.add_argument("-c", "--current", metavar='FILEPATH', type=str,
                          help="specify the full path to the current results file")
    required.add_argument("-s", "--settings", metavar='FILEPATH', type=str,
                          help="specify the full path to the Amaroq settings file")    
    required.add_argument("-d", "--output-directory", metavar='DIR', type=str,
                          help="specify the directory for the SARIF output file")
    required.add_argument("-o", "--output-filename", metavar='FILENAME', type=str,
                          help="specify the name for the SARIF output file")
    required.add_argument("-t", "--tool", nargs=1, metavar='TOOL', type=str, choices=supportedTools, default="GenericSarif",
                          help="Tool format: {tools} (default: %(default)s)".format(tools='|'.join(supportedTools).strip('|')))

    optional = parser.add_argument_group('optional')
    optional.add_argument("-p", "--previous", metavar='FILEPATH', type=str,
                          help="path to a previous SARIF baseline file path")
    optional.add_argument("-f", "--force", action="store_true",
                          help="force overwrite output files")
    optional.add_argument("-a", "--active-only", action="store_true",
                          help="create an additional output file with active results")
    optional.add_argument("--organization-id", type=str, metavar='GUID',
                          help="The Organization Id associated results with.")                          
    optional.add_argument("--project-id", type=str, metavar='GUID',
                          help="The Project Id associated results with.")                          

    return parser

def main():
    parser = build_args()
    args = parser.parse_args()
    #current timestamp for logs and run properties
    currenttime = datetime.datetime.now()
    currentTimestamp = currenttime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # configure logging
    verbose = args.verbose
    loglevel = logging.INFO
    if verbose > 0:
        loglevel = logging.DEBUG

    # default log file location to bin directory
    logFileName = "amaroq_{timestamp}.log".format(timestamp=currenttime.strftime("%y%m%d%H%M%S.%F"))

    # override to output dir if exists
    if args.output_directory and os.path.isdir(args.output_directory):
        logFileName = os.path.join(os.path.abspath(
            args.output_directory), logFileName)

    logging.basicConfig(
        level=loglevel,
        format="%(message)s",
        handlers=[
            logging.FileHandler(logFileName),
            logging.StreamHandler()
        ]
    )

    try:
        if args.version:
            print_art()
            exit(0)

        # Validate args
        InvalidArgs = False

        # check required fields
        if not args.current:
            logging.info("Argument error: Current results file is required.")
            InvalidArgs = True

        if not args.output_directory:
            logging.info("Argument error: Output directory is required.")
            InvalidArgs = True

        if not args.output_filename:
            logging.info("Argument error: Output file name is required.")
            InvalidArgs = True

        if not args.organization_id:
            logging.info("Argument error: Current Organization Id is required.")
            InvalidArgs = True

        if not args.project_id:
            logging.info("Argument error: Current Project Id is required.")
            InvalidArgs = True

        # check output directory
        if not os.path.isdir(args.output_directory):
            logging.info("Argument error: Output directory was not found.")
            InvalidArgs = True

        if not args.settings:
            logging.info("Argument error: Settings file is required.")
            InvalidArgs = True
        # output directory
        outputDirectory = os.path.abspath(args.output_directory)

        # output file name
        outputFilePath = os.path.join(outputDirectory, args.output_filename)

        # set summary file name
        summaryFilePath = os.path.join(outputDirectory, "summary_{basename}.json".format(
            basename=os.path.splitext(os.path.basename(outputFilePath))[0]))

        # set active file name
        activeFileName = os.path.join(
            outputDirectory, "active_" + args.output_filename)

        # check output file
        if os.path.isfile(outputFilePath):
            if args.force:
                logging.debug("Removing: \"{}\"".format(
                        outputFilePath))
                os.remove(outputFilePath)
            else:
                logging.info("Argument error: Output file already exits.")
                InvalidArgs = True

        # check summary output file
        if os.path.isfile(summaryFilePath):
            if args.force:
                logging.debug("Removing: \"{}\"".format(
                        summaryFilePath))
                os.remove(summaryFilePath)
            else:
                logging.info(
                    "Argument error: Summary output file already exits.")
                InvalidArgs = True

        # check active output file
        if args.active_only and os.path.isfile(activeFileName):
            if args.force:
                logging.debug("Removing: \"{}\"".format(
                        activeFileName))
                os.remove(activeFileName)
            else:
                logging.info("Argument error: Active only file already exits.")
                InvalidArgs = True

        # check current results file
        if not os.path.isfile(str(args.current)):
            logging.info("Argument error: Current results file was not found.")
            InvalidArgs = True
        
        # check settings file
        if not os.path.isfile(str(args.settings)):            
            logging.info("Argument error: Amaroq settings file was not found.")
            InvalidArgs = True            

        # check previous results file
        if args.previous and not os.path.isfile(str(args.previous)):
            logging.info(
                "Argument error: Previous results file was not found.")
            InvalidArgs = True

        # Check if args are valid
        if (InvalidArgs == True):
            logging.info("")
            parser.print_help()
            exit(-1)

        # args are good, print banner + version and move forward
        print_art()

        logging.debug("Arguments: \"{}\"".format(args))

        # Convert sarif log file
        try:            
            tempFileName = "{basename}_{timestamp}.sarif".format(
                basename=os.path.splitext(os.path.basename(outputFilePath))[0],
                timestamp=datetime.datetime.now().strftime("%y%m%d%H%M%S"))
            normalizedFileOutput = os.path.join(
                outputDirectory, tempFileName)            

            validateSettings(settings=args.settings)

            logging.debug(
                "Creating temp conversion file {}".format(normalizedFileOutput))

            logging.info("Phase 1: Performing Data Transformation")
            convert_sarif_log(resultInput=args.current,
                              sarifOutput=normalizedFileOutput, targetTool=args.tool[0])

            logging.info("Phase 2: Performing Differential Analysis")
            diff_sarif_log(baseline=args.previous,
                           current=normalizedFileOutput, fileOutput=outputFilePath)

            logging.info("Phase 3: Applying Suppression rules")
            suppress_sarif_log(sarifResults=outputFilePath, targetTool=args.tool[0], settingsFile=args.settings)

            logging.info("Phase 4: Analyzing Vulnerability Results")
            summary_sarif_log(projectId=args.project_id, organizationId=args.organization_id, targetTool=args.tool[0], activeResults=args.active_only,
                              sarifResults=outputFilePath, summaryResults=summaryFilePath, runtimestamp=currentTimestamp)                        
            logging.info("Phase 5: Generating Amaroq metadata")
            apply_amaroq_metadata(sarifResults=outputFilePath, projectId=args.project_id, organizationId=args.organization_id)

        except Exception as e:
            raise e
        finally:
            if os.path.isfile(normalizedFileOutput):
                os.remove(normalizedFileOutput)
    except subprocess.CalledProcessError as error:
        logging.error("error code", error.returncode, error.stderr)
        exit(error.returncode)
    except Exception as e:
        logging.error(e)
        exit(9000)


if __name__ == "__main__":
    main()
