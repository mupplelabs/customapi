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
    match time :
        case float() :
            # start_time is in seconds
            timestamp = time
        case int() :
            # start_time is in seconds with ms precision 
            timestamp = float(time) 
        case str() :
            timestamp = checkTimeString(time, tag)
        case datetime.datetime() :
            timestamp = time.timestamp()
        case _ :
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
        topic (str): The topic of the logs to retrieve. Defaults to "protocol".
        limit (int): The number of entries to limit the result to. Defaults to 1000. -1 for no limit.
        start_time (int/str/float/datetime.datetime): The start time of the time range to retrieve logs for. Defaults to 0.
        end_time (int/str/float/datetime.datetime): The end time of the time range to retrieve logs for. Defaults to None.

    Returns:
        tuple: A tuple containing a status string and a dictionary.
            If the status is "success", the dictionary contains a key "entries" with a list of audit log entries, a key "count" with the number of entries, and a key "resume_ts" with the timestamp of the last entry in the result if the result is limited.
            If the status is "failed", the dictionary contains a key "error" with an error message.
    """
    # validate time arguments
    try: 
        start_time_seconds = validateTimeType(start_time, "start_time") if start_time else 0
        end_time_seconds   = validateTimeType(end_time, "end_time") if end_time else None
    except Exception as e :
        return "failed", { 'error' : str(e), 'error_code' : 400, "status" : "400 Bad Request" }

    entries     : list = []
    entry       : dict = {}
    count       : int = 0    

    try :
        with util.Viewer(node_id, topic, start_time_seconds) as viewer :
            payload = viewer.get(block=False)
            while payload:
                entry = json.loads(payload)
                payload = viewer.get(block=False)
                if end_time != None and entry.get('timestamp', 1000000) / 1000000 > end_time_seconds :
                    break # or should we "pass" here? in other words is it safe to assume the audit log is sorted? 
                else : 
                    count += 1
                    entries.append(entry)
                if limit != -1 and count >= limit :
                    break
            response = { 'entries' : entries, 'count' : count }
            if limit != -1 and count >= limit :
                print(f"Limiting result to {limit} entries")
                response['resume_ts'] = entry.get('timestamp', 1000000) / 1000000   
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

Request Body: None

Response Schema:
{json.dumps(audit_doc['GET_output_schema'], indent=4)}"""
    
    if get_json :
        return audit_doc
    else :
        return Description_text