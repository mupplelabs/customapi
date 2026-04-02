from __future__ import annotations  
from isi.audit import util
import datetime
import json

def checkTimeString(time:str, tag:str = "time") -> float :
    """
    Converts a given time string to EPOCH time.

    Args:
        time (str): The time string to convert in the format 'YYYY-MM-DD HH:MM:SS'

    Returns:
        float: The EPOCH time corresponding to the given time string

    Raises:
        ValueError: If the given time string is invalid
    """
    try:
        ts = datetime.datetime.strptime(time, '%Y-%m-%d %H:%M:%S').timestamp()
    except ValueError:
        try :
            ts = float(time)
        except ValueError :
            raise ValueError(f"Invalid time format: {time}. Please check that the {tag} is in the format 'YYYY-MM-DD HH:MM:SS'")
    return ts

def validateTimeType(time, tag:str = "start_time") -> float :
    """
    Validates the given time argument against a set of supported types and returns the corresponding EPOCH time.

    Args:
        time: The time argument to validate. Must be one of the supported types.
        tag (str): The tag to use in error messages. Defaults to "start_time".

    Returns:
        float: The EPOCH time corresponding to the given time argument.

    Raises:
        TypeError: If the given time argument is not one of the supported types.
        ValueError: If the given time argument exceeds the unix epoch maximum.
    """
    if isinstance(time, datetime.datetime) :
        timestamp = time.timestamp()
    elif isinstance(time, str) :
        timestamp = checkTimeString(time, tag)
    elif isinstance(time, float) :
        timestamp = time
    elif isinstance(time, int) :
        timestamp = float(time)
    else :
        supported_types : list = ["datetime.datetime", "str", "float", "int"]
        raise TypeError(f"{tag} must be one of the following types: {', '.join([t for t in supported_types])}, not {type(time).__name__}")
    
    # test if times exceed unix epoch maximum
    if timestamp >= 2147483647 :
        raise ValueError(f"{tag} must not exceed unix epoch maximum")
    
    return timestamp
        
def auditViewer(node_id : str, topic : str = "protocol", limit : int = 1000, start_time = 0, end_time = None) -> tuple[str, dict] :
    """
    Retrieves information from OneFS audit logs.

    Parameters:
        node_id (str): The ID of the node to retrieve audit information from.
        topic (str)  : The topic of the logs to retrieve. Defaults to "protocol".
        limit (int)  : The number of entries to limit the result to. Defaults to 1000. -1 for no limit.
        start_time (int/str/float/datetime.datetime): The start time of the time range to retrieve logs for. Defaults to 0.
        end_time (int/str/float/datetime.datetime)  : The end time of the time range to retrieve logs for. Defaults to None.

    Returns:
        tuple: A tuple containing a status string and a dictionary.
            If the status is "success", the dictionary contains a key "entries" with a list of audit log entries, a key "count" with the number of entries, and a key "resume_ts" with the timestamp of the last entry in the result if the result is limited.
            If the status is "failed", the dictionary contains a key "error" with an error message.
    """
    # validate time arguments
    try: 
        start_time_seconds = validateTimeType(start_time, "start_time") if start_time else 0.0
        end_time_seconds   = validateTimeType(end_time, "end_time") if end_time else None
    except Exception as e :
        return "failed", { 'error' : str(e), 'error_code' : 400, "status" : "400 Bad Request" }

    if end_time and start_time_seconds > end_time_seconds :
        return "failed", { 'error' : "start_time must be less than end_time", 'error_code' : 400, "status" : "400 Bad Request" }    

    entries     : list = []
    entry       : dict = {}
    count       : int = 0    

    try :
        with util.Viewer(node_id, topic, start_time_seconds) as viewer :
            payload = viewer.get(block=False)
            while payload:
                entry = json.loads(payload)
                payload = viewer.get(block=False)
                if not start_time_seconds.is_integer() and entry.get('timestamp', 1000000) / 1000000 < start_time_seconds :
                    continue # if start_time is NOT an integer, skip entries that are before start_time with full precision
                if end_time != None and entry.get('timestamp', 1000000) / 1000000 > end_time_seconds :
                    break # or should we "pass" here? in other words is it safe to assume the audit log is sorted? 
                count += 1
                if limit != -1 and count > limit :
                    break # if we have reached the limit, break
                else :
                    entries.append(entry)
            response = { 'entries' : entries, 'count' : len(entries) }
            if limit != -1 and count > limit :
                response['resume_ts'] = float(entry.get('timestamp', 1000000) / 1000000)   
            else :
                response['resume_ts'] = None
            return "success", response
    except Exception as e :
        return "failed", { 'error' : str(e) , 'error_code' : 500, "status" : "500 Internal Server Error" }

def auditViewer_describe(myAPI : str, endpoint_version : int, privileges : list, get_json:bool = False) :
    """Returns the API documentation for the audit viewer endpoint."""
    ResourcePath = f"/{myAPI}/{endpoint_version}/audit_viewer"
    audit_doc =  { 
        "GET_args": {
            "description": "An endpoint to retrieve information from OneFS audit logs.",
            "properties": 
            {
                "node_id": {
                    "description": "The ID of the node to retrieve audit information from.",
                    "type": "integer",
                    "required": True
                },
                "topic": {
                    "description": "The topic to retrieve audit information for.",
                    "type": "string",
                    "values": ["protocol", "config"],
                    "required": True
                },
                "start_time": {
                    "description": "Audit log start time (epoch seconds).",
                    "type": ["integer", "float", "string"],
                    "default": 0
                },
                "end_time": {
                    "description": "Audit log end time (epoch seconds).",
                    "type": ["integer", "float", "string"],
                    "default": None  
                }
            },
            "type": "object",
            "privileges": f"{privileges}"
        },
        "GET_output_schema": 
        {
            "type": "object",
            "properties": 
            {
                "error": {
                    "type": "string"
                },
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
        },
        "GET_error_schema":{
            "type": "object",
            "description": "A list of errors that may be returned.",
            "additionalProperties": False,
            "properties": {
                "errors": {
                "type": "array",
                "items": {
                    "type": "object",
                    "description": "An object describing a single error.",
                    "additionalProperties": False,
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
    }

    Description_text =  f"""Resource URL: {ResourcePath}
{audit_doc['GET_args']['description']}

Accepted methods: ['GET']
Privileges: {privileges} 
Arguments:
    node_id (str): The ID of the node to retrieve audit information from.
    topic (str): The topic of the logs to retrieve. Defaults to "protocol".
    limit (int): The number of entries to limit the result to. Defaults to 1000. -1 for no limit.
    start_time (int/str/float): The start time of the time range to retrieve logs for. Defaults to 0.
    end_time (int/str/float): The end time of the time range to retrieve logs for. Defaults to None.  

    Note: start_time and end_time strings are expected to be formatted as 'YYYY-MM-DD HH:MM:SS' 

Application Notes:

    - The logs are per Node; it is not currently possible to get data from a full cluster in a single call.

Request Body: None

Response Schema:
{json.dumps(audit_doc['GET_output_schema'], indent=4)}

Error Schema:
{json.dumps(audit_doc['GET_error_schema'], indent=4)}"""
    
    if get_json :
        return audit_doc
    else :
        return Description_text