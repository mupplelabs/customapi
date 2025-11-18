# Custom API for OneFS

This script adds a custom api to OneFS to provide customizable REST API endpoints such as:

- isi_s3_setkey - and endpoint to set s3 access keys and secrets with custom values
- quotas - prefiltered quota management from non-system zones
- sysctls - returns the values of a configurable set of sysctls
- pass thru - non-filtered pass thru of system zone exclusive papi endpoints into a given access zone.

The customapi comes with documentation built in. </br>
Access <a>https://\<your-cluster-or-node\>:8080/customapi</a> to get a list of available endpoints.

For more information on any specific endpoint, you can send a GET request to that
endpoint with the query arg "describe" appended, for example:
 <a>https://\<your-cluster-or-node\>:8080/{api_endpoint}/<endpoint>?describe</a>

The API is built ontop of FLASK with added OneFS Specific authorization to secure access from non-system access zones.
Endpoints can be individually configured, disabled and enabled as required via a simple configuration file.

Status of the Service can be controlled via an easy to use control script.

## Requirements
The code is written in python and requires version 3.8 minimum and has been tested with OneFS 9.12.
The api requires changes to the clusters webui_httpd.config, to automate startup of the script it self a custom crontab is required in addition.

## Security:
To make this work the apache proxy modules are required. Note: these are disabled if the STIG hardening profiles are enabled on a cluster!

## Installation
- Copy the 'tar.gz' package and install script `installer.py` to `/ifs/data/Isilon_Support/`
- cd into `/ifs/data/Isilon_Support/`
run the script:
```
# python ./installer.py install 
```
## Un-Install
To uninstall the custom API run the control tool (technically the same script as the installer).
```
# isi_customapi remove 
```
If you want to remove it from the cluster completely run:
```
# isi_customapi remove --delete-from-ifs
```
## Configuration
Customapi can be configured in a ini-file-style configuration file.
The syntax and of the configurationshould be easy to use and self-explanatory.</br>
Find the file: ```/ifs/data/Isilon_Support/customapi/api_config.ini```</br>

It allows to disable, enable routes, per API route permissions as well as global app settings.</br>

```
[app]
# Common API settings go here.
api_port = 8000
app-logging = True
loglevel = ERROR
logfile = /tmp/custom_api_error.log
access-logging = False
access-log-file = /tmp/custom_api_access.log

[isi_s3_setkey]
# Endpoint to set S3 keys to a specified string. Requires RPQ and tie isi_s3_setkey binary installed on each node.
enabled = True
bin_path = /usr/bin/isi_s3_setkey
privileges = ["ISI_PRIV_LOGIN_PAPI", "ISI_PRIV_S3"]
zones = ["System"]

# Additional configuration keys that can be used to configure commonly available security options.
# zones         = ["all"]                   # takes a list of Zones the endpoint is available in
# privileges    = ["ISI_PRIV_LOGIN_PAPI"]   # a list of Privileges the endpoint requires user MUST have all named permissions!
# rbac_role     = "ISI_RR_SUDO"             # name of the RBAC Role that the endpoint requires
# username      = "admin"                   # name of the user that the endpoint requires
# group         = "administrators"          # name of the group that the endpoint requires

```
Note any configuration change requires the api to be restarted.
```
# isi_customapi restart
```
## The api control tool
Custom API comes with its own control script. The script is effectively identical with the install script.</br>
It is put into ```/usr/bin``` during initial installation.

```
# isi_customapi --help
usage: isi_customapi [-h]  ...

isi_customapi 0.1.0 - Custom API installer for PowerScale

Installs and controls the custom API serivce on the cluster

optional arguments:
  -h, --help  show this help message and exit

Commands:

    install   Install the custom API
    remove    Uninstall the custom API
    start     Start the custom API
    stop      Stop the custom API
    restart   Restart the custom API
    status    Check the status of the custom API

For mor details on a command, use:
        isi_customapi <command> --help
```
## Self documentation - PAPI Style
<a>https://\<your-cluster-or-node\>:8080/customapi</a> 

```
Welcome to the custom REST API v.19.
    
    With great power comes great responsibility. - Use at your own risk.
    This API allows you to make HTTP calls to the interfaces listed below.

    For more information on any specific endpoint, you can send a GET request to that
    endpoint with the query arg "describe" appended, for example:

    https://<your-cluster-or-node>:8080/customapi/<endpoint>?describe

    Available endpoints:

	/18/protocols/s3/keys/<USER>
	/18/sysctls
	/18/cluster/identity
	/6/snapshot/snapshots
```


