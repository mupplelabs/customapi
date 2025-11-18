import json

def get_s3_keys_doc(myAPI, endpoint_version, privileges, get_json = False):
    Ressource_URL = f"/{myAPI}/{endpoint_version}/protocols/s3/keys/<USER>"
    s3_keys_doc = {
        "DELETE_args": {
            "description": "Delete secret key information for given user.",
            "properties": {
                "zone": {
                    "description": "Specifies access zone containing user.",
                    "type": "string"
                }
            },
            "type": "object"
        },
        "GET_args": {
            "description": "Get access ID information for given user.",
            "properties": {
                "zone": {
                    "description": "Specifies access zone containing user.",
                    "type": "string"
                }
            },
            "type": "object"
        },
        "GET_output_schema": {
            "type": [
                {
                    "additionalProperties": False,
                    "description": "A list of errors that may be returned.",
                    "properties": {
                        "errors": {
                            "items": {
                                "additionalProperties": False,
                                "description": "An object describing a single error.",
                                "properties": {
                                    "code": {
                                        "description": "The error code.",
                                        "maxLength": 8192,
                                        "minLength": 1,
                                        "type": "string"
                                    },
                                    "field": {
                                        "description": "The field with the error if applicable.",
                                        "maxLength": 8192,
                                        "minLength": 1,
                                        "type": "string"
                                    },
                                    "message": {
                                        "description": "The error message.",
                                        "maxLength": 8192,
                                        "minLength": 1,
                                        "type": "string"
                                    }
                                },
                                "type": "object"
                            },
                            "maxItems": 65535,
                            "minItems": 1,
                            "type": "array"
                        }
                    },
                    "type": "object"
                },
                {
                    "additionalProperties": False,
                    "properties": {
                        "keys": {
                            "properties": {
                                "access_id": {
                                    "description": "S3 Access ID",
                                    "maxLength": 272,
                                    "minLength": 9,
                                    "required": False,
                                    "type": "string"
                                },
                                "old_key_expiry": {
                                    "description": "Time that previous secret key will expire, in format YYYY-MM-DD HH:MM:SS",
                                    "required": False,
                                    "type": [
                                        "integer",
                                        "null"
                                    ]
                                },
                                "old_key_timestamp": {
                                    "description": "Time that previous secret key was created, in format YYYY-MM-DD HH:MM:SS",
                                    "required": False,
                                    "type": [
                                        "integer",
                                        "null"
                                    ]
                                },
                                "secret_key_timestamp": {
                                    "description": "Time that secret key was created, in format YYYY-MM-DD HH:MM:SS",
                                    "required": False,
                                    "type": [
                                        "integer",
                                        "null"
                                    ]
                                }
                            },
                            "required": True,
                            "type": "object",
                            "x-privilege": f"{privileges}"
                        }
                    },
                    "type": "object"
                }
            ]
        },
        "POST_args": {
            "description": "Set a new secret key/access ID for given user.",
            "properties": {
                "zone": {
                    "description": "Specifies access zone containing user.",
                    "type": "string"
                }
            },
            "type": "object"
        },
        "POST_input_schema": {
            "properties": {
                "secretkey": {
                    "required": True,
                    "minimum": 8,
                    "type": "string",
                    "description": "Secret key",
                    "maximum": 28
                },
                "existing_key_expiry_time": {
                    "description": "Time from now in minutes that previous secret key will expire.",
                    "maximum": 1440,
                    "minimum": 0,
                    "required": False,
                    "type": "integer"
                }
            },
            "required": True,
            "type": "object",
            "x-privilege": f"{privileges}"
        },
        "POST_output_schema": {
            "type": [
                {
                    "additionalProperties": False,
                    "description": "A list of errors that may be returned.",
                    "properties": {
                        "errors": {
                            "items": {
                                "additionalProperties": False,
                                "description": "An object describing a single error.",
                                "properties": {
                                    "code": {
                                        "description": "The error code.",
                                        "maxLength": 8192,
                                        "minLength": 1,
                                        "type": "string"
                                    },
                                    "field": {
                                        "description": "The field with the error if applicable.",
                                        "maxLength": 8192,
                                        "minLength": 1,
                                        "type": "string"
                                    },
                                    "message": {
                                        "description": "The error message.",
                                        "maxLength": 8192,
                                        "minLength": 1,
                                        "type": "string"
                                    }
                                },
                                "type": "object"
                            },
                            "maxItems": 65535,
                            "minItems": 1,
                            "type": "array"
                        }
                    },
                    "type": "object"
                },
                {
                    "additionalProperties": False,
                    "properties": {
                        "keys": {
                            "properties": {
                                "access_id": {
                                    "description": "S3 Access ID",
                                    "maxLength": 272,
                                    "minLength": 9,
                                    "required": False,
                                    "type": "string"
                                },
                                "old_key_expiry": {
                                    "description": "Time that previous secret key will expire, in format YYYY-MM-DD HH:MM:SS",
                                    "required": False,
                                    "type": [
                                        "integer",
                                        "null"
                                    ]
                                },
                                "old_key_timestamp": {
                                    "description": "Time that previous secret key was created, in format YYYY-MM-DD HH:MM:SS",
                                    "required": False,
                                    "type": [
                                        "integer",
                                        "null"
                                    ]
                                },
                                "secret_key": {
                                    "description": "Secret key",
                                    "maxLength": 255,
                                    "minLength": 1,
                                    "required": False,
                                    "type": "string",
                                    "x-sensitive": True
                                },
                                "secret_key_timestamp": {
                                    "description": "Time that secret key was created, in format YYYY-MM-DD HH:MM:SS",
                                    "required": False,
                                    "type": [
                                        "integer",
                                        "null"
                                    ]
                                }
                            },
                            "required": True,
                            "type": "object",
                            "x-privilege": f"{privileges}"
                        }
                    },
                    "type": "object"
                }
            ]
        }
    }
    Description_text =  f"""Resource URL: {Ressource_URL}
()
    Overview: This resource applies the standard collection pattern to S3
              Secret Keys and Access IDs for Admin.
()
     Methods: GET, POST, DELETE

********************************************************************************

Method GET: {s3_keys_doc['GET_args']['description']}.
()
URL: GET {Ressource_URL}

Query arguments:
zone=<string> Specifies access zone containing user.

GET response body schema:

{json.dumps(s3_keys_doc.get('GET_output_schema', {}), indent=4)}

********************************************************************************

Method POST: {s3_keys_doc['POST_args']['description']}
()
URL: POST /{Ressource_URL}

Query arguments:
    zone=<string> Specifies access zone containing user.

POST request body schema:

{json.dumps(s3_keys_doc.get('POST_input_schema', {}), indent=4)}

POST response body schema:

{json.dumps(s3_keys_doc.get('POST_output_schema', {}), indent=4)}

********************************************************************************

Method DELETE: {s3_keys_doc['DELETE_args']['description']}
()
URL: DELETE /{Ressource_URL}

Query arguments:
    zone=<string> Specifies access zone containing user.

There is no JSON response body for this method.
"""
    if get_json :
        return json.dumps(s3_keys_doc, indent=4)
    else :
        return Description_text