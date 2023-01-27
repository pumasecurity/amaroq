import json
import jsonschema
import yaml
import logging
import datetime

amaroq_settings_schema = {
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Generated schema for Root",
  "type": "object",
  "properties": {
    "version": {
      "type": "string"
    },
    "settings": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "tool": {
            "type": "string"
          },
          "version": {
            "type": "string"
          },
          "suppressions": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "alias": {
                  "type": "string"
                },
                "status": {
                  "type": "string"
                },
                "justification": {
                  "type": "string"
                },
                "expiryUtc": {
                  "type": "string",
                 "pattern":"^\\d{4}-(0?[1-9]|1[0-2])-(0?[1-9]|[12][0-9]|3[01]) (00|[0-9]|1[0-9]|2[0-3]):([0-9]|[0-5][0-9]):([0-9]|[0-5][0-9])(?:\\.\\d+)?$"
                },
                "results-guids": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                "expression": {
                  "type": "string"
                }
              },
              "required": [
                "alias",
                "status",
                "justification"
              ],
              "oneOf": [
                {
                    "required": [
                        "results-guids"
                    ]
                },
                {
                    "required": [
                        "expression"
                    ]
                }               
            ]
            }
          },
          "thresholds": {
            "type": "array",
            "items": {
              "type": "string"
            }
          }
        },
        "required": [
          "tool",
          "version",
          "suppressions"
        ]
      }
    }
  },
  "required": [
    "version",
    "settings"
  ]
}

def datetimeConverter(o):
 if isinstance(o, datetime.datetime):
    return o.__str__()

def validateSettings(settings:str):
  try:
    settingsData = None    
    with open(settings, "r") as stream:
        try:
            settingsData = yaml.safe_load(stream)            
        except yaml.YAMLError as exc:
            logging.error("Error loading settings:")
            if hasattr(exc, 'problem_mark'):
                mark = exc.problem_mark
                logging.error("Error position: (%s:%s)" % (mark.line+1, mark.column+1))
                raise Exception("Error position: (%s:%s)" % (mark.line+1, mark.column+1))
            else:
                logging.error(exc)
                raise Exception(exc)
                
    settingsJsonObject = json.loads(json.dumps(settingsData, default=datetimeConverter))
    jsonschema.validate(
        instance=settingsJsonObject,
        schema=amaroq_settings_schema)
    logging.info("Settings Validation: Passed")
  except jsonschema.ValidationError as error:
      logging.error("Settings Validation: Failed!")
      raise error
    
      