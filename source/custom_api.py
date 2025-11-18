#! /bin/env python3

__doc__         = 'Custom API for the OneFS PAPI.'
__version__     = '0.1.0'
__author__      = 'Stephan Esche'
__contact__     = 'stephan.esche@dell.com'
__copyright__   = 'Copyright (C) 2020-2025, Dell Inc. All rights reserved.'
__api_version__ = '1' # API version, starting with the current version of the PAPI (OneFS9.7.0)

import os
import sys
from pathlib import Path
import re
import subprocess
import configparser
from flask import Flask, request, Response, jsonify, cli, abort
from flask.logging import default_handler
from isi.papi import basepapi
import json
import logging
from logging.handlers import RotatingFileHandler
import urllib3
urllib3.disable_warnings()

from functools import lru_cache
from isi_authorizer import isi_auth, CacheTTLHash

error_code_mapping = {
    "AEC_TRANSIENT": 
        {
        "Description": "The specified request returned a transient error code that is treated as OK.", 
        "HTTP status": "200 OK",
        "HTTP error code": 200
        },
    "AEC_BAD_REQUEST": 
        {
        "Description": "The specified request returned a bad request error.", 
        "HTTP status": "400 Bad Request",
        "HTTP error code": 400
        },
    "AEC_ARG_REQUIRED": 
        {
        "Description": "The specified request requires an argument for the operation.", 
        "HTTP status": "400 Bad Request",
        "HTTP error code": 400
        },
    "AEC_ARG_SINGLE_ONLY": 
        {
        "Description": "The specified request requires only a single argument for the operation.", 
        "HTTP status": "400 Bad Request",
        "HTTP error code": 400
        },
    "AEC_UNAUTHORIZED": {
        "Description": "The specified request requires user authentication.", 
        "HTTP status": "401 Unauthorized",
        "HTTP error code": 401
        },
    "AEC_FORBIDDEN": {
        "Description": "The specified request was denied by the server. Typically, this response includes permission errors on OneFS.", 
        "HTTP status": "403 Forbidden",
        "HTTP error code": 403
        },
    "AEC_NOT_FOUND": {
        "Description": "The specified request has a target object that was not found.", 
        "HTTP status": "404 Not Found",
        "HTTP error code": 404
        },
    "AEC_METHOD_NOT_ALLOWED": {
        "Description": "The specified request sent a method that is not allowed for the target object.", 
        "HTTP status": "405 Method Not Allowed",
        "HTTP error code": 405
        },
    "AEC_NOT_ACCEPTABLE": {
        "Description": "The specified request is unacceptable.", 
        "HTTP status": "406 Not Acceptable",
        "HTTP error code": 406
        },
    "AEC_CONFLICT": {
        "Description": "The specified request has a conflict that prevents the operation from completing.", 
        "HTTP status": "409 Conflict",
        "HTTP error code": 409,
        },
    "AEC_PRE_CONDITION_FAILED": {
        "Description": "The specified request has failed a precondition.", 
        "HTTP status": "412 Precondition failed",
        "HTTP error code": 412
        },
    "AEC_INVALID_REQUEST_RANGE": {
        "Description": "The specified request has requested a range that cannot be satisfied.", 
        "HTTP status": "416 Requested Range not Satisfiable",
        "HTTP error code": 416
        },
    "AEC_NOT_MODIFIED": {
        "Description": "The specified request was not modified.", 
        "HTTP status": "304 Not Modified",
        "HTTP error code": 304
        },
    "AEC_LIMIT_EXCEEDED": {
        "Description": "The specified request exceeded the limit set on the server side.", 
        "HTTP status": "403 Forbidden",
        "HTTP error code": 403
        },
    "AEC_INVALID_LICENSE": {
        "Description": "The specified request has an invalid license.", 
        "HTTP status": "403 Forbidden",
        "HTTP error code": 403
        },
    "AEC_NAMETOO_LONG": {"Description": "The specified request has an object name size that is too long.", 
        "HTTP status": "403 Forbidden",
        "HTTP error code": 403
        },
    "AEC_SYSTEM_INTERNAL_ERROR": {
        "Description": "The specified request has failed because the server encountered an unexpected condition.", 
        "HTTP status": "500 Internal Server Error",
        "HTTP error code": 500
        }
    }

log_level_mapping = {
    'DEBUG'     : logging.DEBUG,
    'INFO'      : logging.INFO,
    'WARN'      : logging.WARN,
    'ERROR'     : logging.ERROR,
    'CRITICAL'  : logging.CRITICAL,
    'NOTSET'    : logging.NOTSET,
    'FATAL'     : logging.FATAL
}

#Basepapi request mapping
method_requests_mapping = {
    'GET'       : basepapi.get,
    'HEAD'      : basepapi.head,
    'POST'      : basepapi.post,
    'PUT'       : basepapi.put,
    'DELETE'    : basepapi.delete,
    'OPTIONS'   : basepapi.options
}

### Configuration handling ###
home_dir = Path(os.path.dirname(os.path.abspath(__file__))).parent
config_ini_path = str(home_dir) + '/api_config.ini'

api_config = configparser.ConfigParser()

try:
    api_config.read(config_ini_path)
except configparser.Error as e:
    logging.error(f"{e}")
    exit(1)

def get_json_from_config(section, key, fallback = None):
    item_str = api_config.get(section, key, fallback=None)
    if item_str is not None:
        try:
            item_json = json.loads(item_str)
        except json.decoder.JSONDecodeError:
            logging.error(f"Invalid JSON in configuration file: in section \"{section}\", key \"{key}\", value \"{item_str}\"")
        else:
            logging.debug(f"retrieved from: {section}, {key} json: {item_str}")
            return item_json
    logging.debug(f"From: {section}, {key} fallback to: {fallback}")
    return fallback
        
# Latest PAPI Version

papi_version = basepapi.get('latest').body['latest']

# Configuration

api_port               = api_config.get('app', 'api_port',                 fallback=8000)
logging_level          = api_config.get('app', 'loglevel',                 fallback='ERROR').upper()
access_logging         = api_config.get('app', 'access-logging',           fallback=False) 
app_logging            = api_config.get('app', 'app-logging',              fallback=True) 
access_log_file        = api_config.get('app', 'access-log-file',          fallback='./access.log') 
log_file               = api_config.get('app', 'logfile',                  fallback=f'./{os.path.basename(__file__)}.log') 

# Endpoint Configuration

quotas_enabled          = api_config.get('quotas', 'enabled',                    fallback=False) 
protect_root_quota      = api_config.get('quotas', 'protect_root_quota',         fallback=True) 
enable_bulk_delete      = api_config.get('quotas', 'enable_bulk_delete',         fallback=False) 
quotas_allowed_zones    = get_json_from_config('quotas', 'zones',                fallback=['all']) 
quotas_privileges       = get_json_from_config('quotas', 'privileges',           fallback=['ISI_PRIV_LOGIN_PAPI'])
quotas_allowed_role     = api_config.get('quotas', 'rbac_role',                  fallback=None)
quotas_allowed_user     = api_config.get('quotas', 'username',                   fallback=None) 
quotas_allowed_group    = api_config.get('quotas', 'group',                      fallback=None)

S3_keyapi_enabled       = api_config.get('isi_s3_setkey', 'enabled',             fallback=False) 
isiS3Command            = api_config.get('isi_s3_setkey', 'bin_path',            fallback="/usr/bin/isi_s3_setkey") 
S3_Privileges           = get_json_from_config('isi_s3_setkey', 'privileges',    fallback=['ISI_PRIV_LOGIN_PAPI', 'ISI_PRIV_S3']) 
S3_allowed_zones        = get_json_from_config('isi_s3_setkey', 'zones',         fallback=['System']) 
S3_rbac_role            = api_config.get('isi_s3_setkey', 'rbac_role',           fallback=None) 
S3_allowed_user         = api_config.get('isi_s3_setkey', 'username',            fallback=None)
S3_allowed_group        = api_config.get('isi_s3_setkey', 'group',               fallback=None)

sysctl_enabled          = api_config.get('sysctl', 'enabled',                    fallback=False) 
sysctl_oids             = get_json_from_config('sysctl', 'oids',                 fallback=[]) 
sysctl_commands         = get_json_from_config('sysctl', 'commands',             fallback=[]) 
sysctl_zones            = get_json_from_config('sysctl', 'zones',                fallback=['System']) 
sysctl_privileges       = get_json_from_config('sysctl', 'privileges',           fallback=['ISI_PRIV_LOGIN_PAPI']) 
sysctl_rbac_role        = api_config.get('sysctl', 'rbac_role',                  fallback=None) 
sysctl_allowed_user     = api_config.get('sysctl', 'username',                   fallback=None) 
sysctl_allowed_group    = api_config.get('sysctl', 'group',                      fallback=None) 

system_enabled          = api_config.get('system', 'enabled',                    fallback=False)
system_endpoints        = get_json_from_config('system', 'papi_endpoints',       {f"/{papi_version}/cluster/identity" : ["GET"], "/latest" : ["GET"]})
system_zones            = get_json_from_config('system', 'zones',                fallback=['System']) 
system_privileges       = get_json_from_config('system', 'privileges',           fallback=['ISI_PRIV_LOGIN_PAPI']) 
system_rbac_role        = api_config.get('system', 'rbac_role',                  fallback=None) 
system_allowed_user     = api_config.get('system', 'username',                   fallback=None) 
system_allowed_group    = api_config.get('system', 'group',                      fallback=None) 

link_api_enabled        = api_config.get('link_api', 'enabled',                  fallback=False)
link_api_privileges     = get_json_from_config('link_api', 'privileges',         fallback=['ISI_PRIV_LOGIN_PAPI']) 
link_api_zones          = get_json_from_config('link_api', 'zones',              fallback=['System']) 
link_api_rbac_role      = api_config.get('link_api', 'rbac_role',                fallback=None) 
link_api_allowed_user   = api_config.get('link_api', 'username',                 fallback=None) 
link_api_allowed_group  = api_config.get('link_api', 'group',                    fallback=None) 

### Flask setup ###
app = Flask(__name__)
cli.show_server_banner = lambda *args: None # disable banner
app.logger.removeHandler(default_handler)

from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1
)

# initialize the authorization extension
isi = isi_auth(app, app.logger)

# Make sure to set the PROPAGATE_EXCEPTIONS configuration to True
app.config['PROPAGATE_EXCEPTIONS'] = True

# configure access logging from stderr to log file
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
log.disabled = True
if access_logging :
    ip_address   = None
    current_user = None
    class CustomRequestFormatter(logging.Formatter):
        def format(self, record):
            if 'werkzeug' in record.name and ip_address :
                record.ip = ip_address
                record.msg = record.msg.replace('127.0.0.1', record.ip)
                record.msg = record.msg.replace('"%s" %s %s', '')
                return '{msg} - {user} - "{args}" - {code} {ext}'.format(user = current_user, args = record.args[0], code = int(record.args[1]), ext = record.args[2], msg = record.msg)
            return super().format(record)
    handler = RotatingFileHandler(access_log_file, maxBytes=1000000, backupCount=5)
    formatter = CustomRequestFormatter()
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.disabled = False    

if app_logging :
    app_log_handler = RotatingFileHandler(log_file, maxBytes=1000000, backupCount=5)
    app_formatter   = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    app_log_handler.setFormatter(app_formatter)
    app_log_handler.setLevel(logging.NOTSET)
    app.logger.handlers.clear()
    app.logger.addHandler(app_log_handler)
    app.logger.setLevel(log_level_mapping[logging_level])
else :
    app.logger.disabled = True

if access_logging :
    @app.before_request
    def set_ip_address():
        global ip_address
        global current_user
        ip_address   = request.headers.get('X-Forwarded-For', request.remote_addr) 
        current_user = request.headers.get('X-Remote-User', 'Unknown')

# Exception handling
class ApiException(Exception):
        def __init__(self, error, message, code):
            self.error   = error
            self.code    = code
            self.message = message
            super().__init__(message)

@app.errorhandler(basepapi.PapiError)
@app.errorhandler(isi.AuthException)
@app.errorhandler(Exception)
def handle_error(e):  # handles any exception thrown in the app
    """
    Handles any exception thrown in the app,
    and returns a json error message and error code

    Args:
        e (Exception): The exception thrown

    Returns:
        json: A json object with the error message and error code
        int: The error code
    """
    if type(e) != basepapi.PapiError : # if we raise a PapiError from basepapi just return it
        app.logger.error(str(e))
        error_code    = getattr(e, 'error', 'AEC_GENERIC_ERROR')
        error_status  = getattr(e, 'code', 500)  # get the error code from the exception, default to 500
        error_message = getattr(e, 'message', 'An unknown error has occurred.')
        if error_status == 500 :
            error_code    = 'AEC_SYSTEM_INTERNAL_ERROR'
            error_message = error_code_mapping.get(error_code, {}).get('Description', 'An internal error has occurred.')
        elif error_status == 404 :
            error_message = error_code_mapping.get('AEC_NOT_FOUND', {}).get('Description', error_message)
        elif error_code != 'AEC_GENERIC_ERROR' :
            error_message = error_code_mapping.get(error_code, {}).get('Description', error_message)
        else :
            app.logger.debug(f"Uncaught error: {e}")
            error_message = error_code_mapping.get(error_code, {}).get('Description', error_message)
        errors = {
                "errors": [
                    {
                        "code"   : error_code,
                        "message": error_message
                    }
                ]
            }
        return jsonify(errors), error_status
    else :
        app.logger.debug(str(e))
        return jsonify(e.body), e.status

def run_command(command: str) -> subprocess.CompletedProcess:
    """
    Run an external command and capture the output and error.

    Args:
        command (str): The command to run

    Returns:
        subprocess.CompletedProcess: The result of the command

    Notes:
        This function runs an external command using the subprocess module.
        The command is executed with shell=True to allow for shell expansion
        and piping. The command output and error are captured and returned
        as a CompletedProcess object.
    """
    app.logger.info(f"Running command: {command}")
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    if result.returncode == 0:
        # The command completed successfully
        return result
    else:
        # The command encountered an error
        app.logger.error(f"error: {result}")
        return result

# here comes the custom API
# Custom S3 API
   
def isi_s3_setkey(user: str, zone: str, s3_key: str, retention: int = 10) :
    """
    Create or update an S3 ID and Key pair with a custom Secret Key.

    Args:
        user (str): The username for which the S3 keys will be created or updated.
        zone (str): The access zone for the S3 keys. Defaults to the current user's zone.
        s3_key (str): The new secret key to set for the user.
        retention (int, optional): The number of minutes the previous secret key will be valid. Defaults to 10. Maximum is 1440.

    Returns:
        Tuple[Dict[str, Any], int]: A dictionary containing the S3 keys and the HTTP status code.

    Raises:
        ApiException: If the command encountered an error.
    """
    command = f"{isiS3Command} -u {user} -z {zone} -t {retention} -s -j {s3_key}"
    result = run_command(command)
    if result.returncode != 0 :
        if any( error in result.stderr for error in ['Unable to validate user', 'Zone']) :
            code = "AEC_NOT_FOUND" 
        elif any( error in result.stderr for error in ['Cannot update']) :
            code = "AEC_PRE_CONDITION_FAILED"
        elif any( error in result.stderr for error in ['Specified secret must not exceed 28 characters!']) :
            code = "AEC_LIMIT_EXCEEDED"
        elif any( error in result.stderr for error in ['Specified secret too short, must be atleast 8 characters!']) :
            code = "AEC_LIMIT_EXCEEDED"
        else :
            code = 'AEC_SYSTEM_INTERNAL_ERROR'
        http_status = error_code_mapping[code]['HTTP status']
        raise ApiException(code, result.stderr, http_status)
    else :
        isi_s3_result = {'keys' : json.loads(result.stdout)}
        return isi_s3_result, 200

if S3_keyapi_enabled :
    app.logger.info("S3 key API enabled")
    @app.route(f'/{__api_version__}/protocols/s3/keys/<string:user>', methods=['GET', 'POST', 'DELETE'])
    @isi.auth(privileges=S3_Privileges, zones=S3_allowed_zones, username=S3_allowed_user, group=S3_allowed_group, role=S3_rbac_role)
    def s3_keys(user):
        """
        This function handles requests to the '/{__api_version__}/protocols/s3/keys/<string:user>' endpoint. It supports the GET, POST, and DELETE methods.
        
        Parameters:
            user (str): The user for which the S3 keys are requested. If not provided, a 400 error is returned.
        
        Returns:
            - If the request method is GET, it returns the S3 keys for the specified user in JSON format along with the HTTP status code.
            - If the request method is DELETE, it deletes the S3 keys for the specified user and returns the response body in JSON format along with the HTTP status code.
            - If the request method is POST, it expects a JSON payload containing a 'secretkey' field. If the 'secretkey' field is missing, a 400 error is returned. 
              Otherwise, it calls the 'isi_s3_setkey' function to set the S3 key for the specified user and returns the result in JSON format along with the HTTP status code.
            - If the 'user' parameter is not provided, a 400 error is returned.
        
        Raises:
            ApiException: If the 'isi_s3_setkey' command encounters an error.
        """
        params  = dict(request.args)
        if 'describe' in params : 
            get_json = 'json' in params
            this_endpoint = request.headers.get('X-api-location', 'unknown')
            from s3_keys_describe import get_s3_keys_doc
            response_text = get_s3_keys_doc(this_endpoint, __api_version__, ['ISI_PRIV_LOGIN_PAPI', 'ISI_PRIV_S3'], get_json=get_json)
            return Response(response_text, mimetype='text/plain' if not get_json else 'application/json', status=200)
        else :
            zone = params.get('zone', isi.access_zone) # default to current users zone
            if isi.access_zone != 'System' and isi.access_zone != zone : # do not allow access to other zones unless you are in the System zone
                        return abort(403)
            elif user :
                if request.method == 'GET' :
                    papiResponse = basepapi.get(f"/{papi_version}/protocols/s3/keys/{user}", args={'zone': zone})
                elif request.method == 'DELETE' :
                    papiResponse = basepapi.delete(f"/{papi_version}/protocols/s3/keys/{user}", args={'zone': zone})
                elif request.method == 'POST' :
                    '''add code to run the shell command "isi_s3_setkey" and return the response'''
                    s3keyjson = request.json
                    if 'secretkey' not in s3keyjson :
                        return jsonify({'error': 'missing key', 'error_code': 400}), 400
                    else :
                        old_key_retention = s3keyjson.get('existing_key_expiry_time', 10)
                        result, result_status = isi_s3_setkey(user=user, zone=zone, s3_key=s3keyjson['secretkey'], retention=old_key_retention)
                        return jsonify(result), result_status
                
                papiResponse.raise_for_status() # if the request failed, raise an exception
                return jsonify(papiResponse.body), papiResponse.status
            else :
                return jsonify({'error': 'missing user', 'error_code': 400}), 400
            
if link_api_enabled :
    from isi.ui.shell import util
    app.logger.info("OneFS link API enabled")
    @app.route(f'/{__api_version__}/link/create', methods=['PUT'])
    @isi.auth(privileges=link_api_privileges, zones=link_api_zones, username=link_api_allowed_user, group=link_api_allowed_group, role=link_api_rbac_role)
    def create_link() :        
        """
        Create a hard or symbolic link between two paths.

        Parameters:
            params (dict): The query parameters.
            payload (dict): The JSON payload containing the source and target paths.

        Returns:
            Response: A JSON response containing the error message if the request failed, or a success message if the link was created successfully.
        Raises:
            ApiException: If the request failed, it raises an ApiException with the appropriate error code and message.
        """
        payload = request.json
        params  = dict(request.args)
        if 'source' not in payload or 'target' not in payload :
            return jsonify({'error': 'missing source or target', 'error_code': 400}), 400
        
        source = os.path.abspath(payload['source'])
        target = os.path.abspath(payload['target']) 
        
        if source[:len(isi.zone_path)] != isi.zone_path: 
            return jsonify({'error': 'source is outside access zone', 'error_code': 'AEC_FORBIDDEN', 'status': 403}), 403
        
        if target[:len(isi.zone_path)] != isi.zone_path: 
            return jsonify({'error': 'target is outside access zone', 'error_code': 'AEC_FORBIDDEN', 'status': 403}), 403
        
        if os.path.exists(target) :
            return jsonify({'error': 'target already exists', 'error_code': 400}), 400
        
        if not os.path.exists(source) :
            return jsonify({'error': 'source does not exist', 'error_code': 400}), 400

        if 'symbolic' in params and params['symbolic'].lower() == 'true' :
            try :
                os.symlink(source, target)
            except OSError as e :
                return jsonify({'error': str(e), 'error_code': 500}), 500
            return jsonify({'message': 'symbolic link created successfully'}), 200
        else :
            try :
                os.link(source, target)
            except OSError as e : 
                return jsonify({'error': str(e), 'error_code': 500}), 500
            return jsonify({'message': 'hardlink created successfully'}), 200

    @app.route(f'/{__api_version__}/link/create', methods=['GET'])
    @isi.auth(privileges=link_api_privileges, zones=link_api_zones, username=link_api_allowed_user, group=link_api_allowed_group, role=link_api_rbac_role)
    def link_create_help() :
        """
        Returns a docstring for the link create endpoint.

        Parameters:
            params (dict): The query parameters.

        Returns:
            Response: A text/plain response containing the docstring if 'describe' is in the query parameters. Otherwise, it raises an ApiException with error code 405.

        Notes:
            The docstring is generated based on the API endpoint's URL, accepted methods, request schema, arguments schema, and response schema.
        """
        params  = dict(request.args)
        if 'describe' in params :
            this_endpoint = request.headers.get('X-api-location', 'unknown')
            description     = f"Resource URL: /{this_endpoint}/{papi_version}/link/create\n\nAn endpoint to create a hard or symbolic link between two paths."
            request_method  = ["PUT"]
            request_schema  = { 'source': 'string', 'target': 'string' }
            args_schema     = { 'symbolic': 'boolean' }
            response_schema = {"message": "symbolic link created successfully"}
            if not 'json' in params :
                response_text = description + 'Accepted methods: \n\n' + '[' + ', '.join(request_method) + ']' + '\n\nArguments:\n\n' + json.dumps(args_schema, indent=4) + '\n\nRequest body:\n\n' + json.dumps(request_schema, indent=4) + '\n\nResponse Schema :\n\n' + json.dumps(response_schema, indent=4)
                return Response(response_text, mimetype='text/plain', status=200)
            else :
                return jsonify({"description": description, "request_methods" : request_method, "request_schema": request_schema, "args_schema": args_schema, "response_schema": response_schema}), 200
        else :
            raise ApiException(error='AEC_METHOD_NOT_ALLOWED')
        
    @app.route(f'/{__api_version__}/link/enum', methods=['GET'])
    @isi.auth(privileges=link_api_privileges, zones=link_api_zones, username=link_api_allowed_user, group=link_api_allowed_group, role=link_api_rbac_role)
    def link_enum() :
        """
        Enumerate hard links in a path.

        Parameters:
            params (dict): The query parameters.

        Returns:
            Response: A JSON response containing the hard link's LIN number and paths.

        Notes:
            The API endpoint takes a 'path' argument in the request body.
            The 'max_paths' query parameter is optional and defaults to 1000.
        """
        payload = request.json
        params  = dict(request.args)
        if 'describe' in params :
            this_endpoint = request.headers.get('X-api-location', 'unknown')
            description     = f"Resource URL: /{this_endpoint}/{papi_version}/link/enum\n\nAn endpoint to enumerate hard links in a path."
            request_method  = ["GET"]
            request_schema  = { 'path': 'string' }
            args_schema     = { 'max_paths': 'integer DEFAULT:1000' }
            response_schema = {
                'lin'   :   'Lin number (integer)',
                'paths' :   '[list (strings)]'
            }
            if not 'json' in params :
                    response_text = description + 'Accepted methods: \n\n' + '[' + ', '.join(request_method) + ']' + '\n\nArguments:\n\n' + json.dumps(args_schema, indent=4) + '\n\nRequest body:\n\n' + json.dumps(request_schema, indent=4) + '\n\nResponse Schema :\n\n' + json.dumps(response_schema, indent=4)
                    return Response(response_text, mimetype='text/plain', status=200)
            else :
                return jsonify({"description": description, "request_methods": request_method, "request_schema": request_schema, "args_schema": args_schema, "response_schema": response_schema}), 200

        if 'path' in payload :
            path = payload['path']
            if path[:len(isi.zone_path)] != isi.zone_path: 
                return jsonify({'error': 'path is outside access zone', 'error_code': 'AEC_FORBIDDEN', 'status': 403}), 403
        
            max_paths = params.get('max_paths', 1000)
            filepath = payload.get('path')
            try :
                myLin = os.stat(filepath)
            except OSError as e :
                return jsonify({'error': str(e), 'error_code': 400}), 400
            # Convert the LIN number to a list of paths
            _ , paths = util.convertLIN([hex(myLin.st_ino)], print_path=False, max_paths=max_paths)
            
            output = {
                'lin' : myLin.st_ino,
                'paths' : paths
            }
        else :
            return jsonify({'error': 'path is required', 'error_code': 400}), 400
        return jsonify(output), 200

# Jim's Sysctl API:    

if sysctl_enabled :
    app.logger.info("Sysctl API enabled")
    @app.route(f'/{__api_version__}/sysctls', methods=['GET'])
    @isi.auth(privileges=sysctl_privileges, zones=sysctl_zones, username=sysctl_allowed_user, group=sysctl_allowed_group, role=sysctl_rbac_role)
    @lru_cache(maxsize=10)
    def sysctl(ttlHASH = CacheTTLHash(3600)) :
        """
        Return the current sysctl values and the output of a set of commands in a json object.

        This function returns a json object with two keys: "sysctl" and "commands".
        "sysctl" contains a dictionary where the keys are the sysctl names and the values are the current values of those sysctls.
        "commands" contains a dictionary where the keys are the names of the commands and the values are the output of those commands.

        If the 'describe' parameter is specified, the response will be a plain text description of the endpoints, the sysctl names, the commands, and the response schema.

        The function uses a cache to reduce the number of sysctl commands that need to be run. The cache is invalidated every 3600 seconds (1 hour).
        """
        del ttlHASH
        params = dict(request.args) # request.args
        this_endpoint = request.headers.get('X-api-location', 'unknown')
        if 'describe' in params :
            description = f"Resource URL: /{this_endpoint}/{papi_version}/protocols/sysctls\n\nReturns a json object of sysctl names and their values plus the output of a defined set of commands."
            sysctl_list = '\n'.join(sysctl_oids)
            cmd_list = '\n'.join(sysctl_commands)
            response_schema = { 'sysctl': 'object of sysctl names with their values', 'commands': 'object of commands with their output' }
            if not json in params :
                response_text = description + '\n\nSysctl names:\n\n' + sysctl_list + '\n\nCommands:\n\n' + cmd_list + '\n\nResponse Schema:\n\n' + json.dumps(response_schema, indent=4)
                return Response(response_text, mimetype='text/plain', status=200)
            else :
                return jsonify({"description": description, "sysctl": sysctl_oids, "commands": sysctl_commands, "response_schema": response_schema}), 200
        def get_sysctls(ttlHASH = None) :
            """
            Return the current sysctl values and the output of a set of commands in a json object.

            This function is cached to reduce the number of sysctl commands that need to be run.
            The cache is invalidated every 3600 seconds (1 hour).
            """
            del ttlHASH
            data = {} 
            data['sysctl'] = {}
            data['commands'] = {}
            status_code = 200 # 200 is the default status code for a successful GET request
            
            # Get the current value of each sysctl and store it in a dict
            for key in sysctl_oids :
                result = run_command(f"sysctl -n {key}")
                if result.returncode != 0:
                    status_code = 422 # wtf?
                    data['sysctl'][key] = result.stderr.rstrip()
                else:
                    data['sysctl'][key] = result.stdout.rstrip()

            # Get the output of each command and store it in a dict
            for cmd in sysctl_commands:
                result = run_command(cmd)
                if result.returncode != 0:
                    status_code = 422
                    data['commands'][cmd] = result.stderr.rstrip()
                else:
                    data['commands'][cmd] = result.stdout.rstrip()

            return data, status_code
        
        data, status_code = get_sysctls(CacheTTLHash(3600))
        return jsonify(data), status_code
    
# System Zone path through
if system_enabled :
    app.logger.info("System API enabled")
    @app.route('/<path:papi_uri>')
    @isi.auth(privileges=system_privileges, zones=system_zones, username=system_allowed_user, group=system_allowed_group, role=system_rbac_role)
    def callback(papi_uri) :
        """
        This function is a callback function for the System Zone route.
        It sends a incoming request to the basepapi
        and returns the response as a json object.
        
        :param uri: The uri passed in the route.
        :type uri: str
        :return: A json object containing the response body and status code.
        :rtype: flask.Response
        """
        papi_uri = '/' + papi_uri
        if papi_uri in system_endpoints.keys() : 
            if request.method in system_endpoints[papi_uri] :
                # Construct the parameters dictionary
                params = dict(request.args)
                if 'describe' in params :
                    params['json'] = True
                
                # Construct the body dictionary
                bofy = request.json if request.is_json else None
            
                # Get the corresponding basepapi function
                papi_function = method_requests_mapping[request.method]
            
                # Send a request to basepapi
                papi_response = papi_function(papi_uri, args=params, body=bofy)
                
                # Raise an exception if the request was not successful
                papi_response.raise_for_status()
            
                # Return the response body as a json object
                return jsonify(papi_response.body), papi_response.status
            else :
                return abort(405)
        else :
            return abort(404)

# create the index page

api_endpoints = []

@app.route('/')
def index() :
    this_endpoint = request.headers.get('X-api-location', 'unknown')
    welcome = f"""Welcome to the custom REST API v.{__version__}.
    
    With great power comes great responsibility. - Use at your own risk.
    This API allows you to make HTTP calls to the interfaces listed below.

    For more information on any specific endpoint, you can send a GET request to that
    endpoint with the query arg "describe" appended, for example:

    https://<your-cluster-or-node>:8080/{this_endpoint}/<endpoint>?describe

    """
    if not 'json' in request.args : 
        response_text = welcome + 'Available endpoints:\n\n\t' + '\n\t'.join(api_endpoints)
        return Response(response_text, mimetype='text/plain')
    else :
        routes ={
            'description': welcome,
            'endpoints': api_endpoints
        }
        return jsonify(routes)

if logging_level == 'DEBUG':
    # This route is used to test the capabilities of the API by returning a large
    # amount of data in JSON format.
    #
    # The function takes a single argument:
    # papi_uri: The URI passed in the route, used to construct the endpoint.
    #
    # The function returns a JSON response containing all the properties of the
    # incoming request.
    #
    # The returned JSON response is structured as follows:
    # {
    #     'endpoint': The URI passed in the route.
    #     'method': The HTTP method used in the request.
    #     'url': The full URL of the request.
    #     'headers': A dictionary containing all the headers in the request.
    #     'args': A dictionary containing all the query arguments in the request.
    #     'data': The data sent in the request, either as a string or a JSON object.
    # }
    @app.route('/test/<path:papi_uri>')
    @isi.auth(privileges=system_privileges, zones=system_zones, username=system_allowed_user, group=system_allowed_group, role=system_rbac_role)
    def test_route(papi_uri) :
        """
        Test the capabilities of the API by returning a large amount of data in JSON format.

        :param papi_uri: The URI passed in the route.
        :type papi_uri: str
        :return: A JSON response containing all the properties of the incoming request.
        :rtype: flask.Response
        """
        # Create a dictionary with all the properties of the incoming request

        test_response = {
            'endpoint': papi_uri,  # The URI passed in the route.
            'method': request.method,  # The HTTP method used in the request.
            'url': str(request.url),  # The full URL of the request.
            'headers': dict(request.headers),  # All the headers in the request.
            'args': dict(request.args) if request.args else None,  # All the query arguments in the request.
            'data': str(request.data) if not request.is_json else request.json  # The data sent in the request, either as a string or a JSON object.
        }

        return jsonify(test_response)
    
def var2tag4doc(var) :
    """
    Replaces URI tags with their corresponding tag names for documentation purposes.

    :param var: The URI string containing tags.
    :type var: str
    :return: The URI string with tags replaced by their tag names.
    :rtype: str
    """
    # Find all the tags in the URI string
    varTags = re.findall(r'<(.*?)>', var)

    # Replace each tag with its corresponding tag name
    for tag in varTags :
        if tag == 'int:endpoint_version' :
            var = var.replace('<' + tag + '>', __api_version__ )
        else :
            var = var.replace(tag , tag.split(':')[1].upper())
    return var

# the main function
if __name__ == '__main__':
    # equipping the app with the routes for self documentation
    Endpoint = {}
    for rule in app.url_map.iter_rules():
        if not rule.endpoint in ['index', 'static', 'callback']:
            app.logger.info('Found Endpoint: ' + rule.endpoint + ' - ' + rule.rule)
            Endpoint[var2tag4doc(rule.rule)] = ', '.join(rule.methods)
    api_endpoints = sorted(Endpoint.keys())
    if system_enabled :
        api_endpoints.extend(sorted(system_endpoints.keys()))

    # start the app
    app.debug = False
    app.logger.info('Starting custom API v.' + __api_version__ + ' on port ' + str(api_port))
    app.run(host='127.0.0.1', port=api_port)