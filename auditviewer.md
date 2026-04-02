# Auditviewer API

An endpoint to retrieve information from OneFS audit logs.</br>

**Resource URL:** /customapi/1/audit_viewer</br>

**Accepted methods:** ```['GET']```
</br>

**Privileges:** ```['ISI_PRIV_LOGIN_PAPI', 'ISI_PRIV_AUDIT']```
</br>

**Arguments:**
</br>
  - node_id (str): The ID of the node to retrieve audit information from.
  - topic (str): The topic of the logs to retrieve. Defaults to "protocol".
  - limit (int): The number of entries to limit the result to. Defaults to 1000. -1 for no limit.
  - start_time (int/str/float): The start time of the time range to retrieve logs for. Defaults to 0.
  - end_time (int/str/float): The end time of the time range to retrieve logs for. Defaults to None.  
  
    **Note:** start_time and end_time strings are expected to be formatted as ```YYYY-MM-DD HH:MM:SS```

**Request Body:** ```None```

**Application Notes:**
- The logs are per Node; it is not currently possible to get data from a full cluster in a single call.
- ~~Even though audit events are logged with a nano second precision ```start_time``` only acts at full second precision.
  </br>The ```end_time``` parameter however applies at full precision.~~
- ~~If the output is limited the API tells you the last timestamp collected.
  </br>Using this for programmatically fetching logs might result in duplicate entries due to the lower precision of ```start_time```.~~



Response Schema:
```
{
    "type": "object",
    "properties": {
        "entries": {
            "type": "array",
            "items": {
                "type": "object"
            }
        },
        "count": {
            "type": "integer",
            "description": "The number of entries in the result."
        },
        "resume_ts": {
            "type": "float",
            "description": "The timestamp of the last entry in the result if the result is limited."
        }
    }
}
```

Error Schema:
```
{
  "type": "object",
  "description": "A list of errors that may be returned.",
  "additionalProperties": false,
  "properties": {
    "errors": {
      "type": "array",
      "items": {
        "type": "object",
        "description": "An object describing a single error.",
        "additionalProperties": false,
        "properties": {
          "code": {
            "description": "The error code.",
            "type": "string",
            "minLength": 1,
            "maxLength": 8192
          },
          "field": {
            "description": "The field with the error if applicable.",
            "type": "string",
            "minLength": 1,
            "maxLength": 8192
          },
          "message": {
            "description": "The error message.",
            "type": "string",
            "minLength": 1,
            "maxLength": 8192
          }
        }
      },
      "minItems": 1,
      "maxItems": 65535
    }
  }
}
```
