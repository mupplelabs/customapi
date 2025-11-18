#!/usr/bin/env python3
__version__     = '0.1.0'
__author__      = 'Stephan Esche'
__copyright__   = 'Copyright (C) 2020-2024, Dell Inc. All rights reserved.'

import os
import sys
import shutil
import tarfile
import argparse
from argparse import RawTextHelpFormatter
import subprocess
import configparser

apiname     = 'customapi'

target_path = '/ifs/data/Isilon_Support/customapi'
archive_file = os.getcwd() + '/custom_api.tgz'

webui_http_modules = \
"""# Custom API requires mod_proxy
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so"""

webui_http_isiAuth = """    IsiAuthServices platform remote-service namespace customapi"""

webui_crontab = \
f"""@reboot                                 root    sleep 60 && /bin/python3 {target_path}/run.py silent
0       *       *       *       *       root    /bin/python3 {target_path}/run.py silent"""

def unpack_archive_with_progress(archive_file, extract_dir):
    if os.path.exists(archive_file):
        try:
            with tarfile.open(archive_file) as tar:
                total_size = sum(member.size for member in tar.getmembers())
                extracted_size = 0

                for member in tar:
                    tar.extract(member, extract_dir)
                    extracted_size += member.size
                    progress = (extracted_size / total_size) * 100
                    sys.stdout.write(f"\rExtracting progress: {progress:.2f}%")
                    sys.stdout.flush()
            sys.stdout.write('\r')
            sys.stdout.flush()
        except tarfile.TarError as e:
            sys.stderr(f"Error: Failed to unpack archive: {e}")
    else :
        sys.stderr(f"Error: Archive file not found: {archive_file}")

def update_api_config(file_path, key, value):
    """
    Update the API configuration file with the new API endpoint.

    :param file_path: The path to the configuration file
    :type file_path: str
    :param apiname: The name of the new API endpoint
    :type apiname: str
    """
    config = configparser.ConfigParser()
    try :
        config.read(file_path)
    except configparser.Error as e:
        print(e)

    if not config.has_section('app'):
        config.add_section('app')
    config.set('app', key, value)
    with open(file_path, 'w') as configfile:
        config.write(configfile)

def modify_webui_config(file_path, webui_http_modules, webui_httpd_location, apiname, api_port):
    """
    Modify the webui configuration file to include the new API endpoint

    :param file_path: The path to the webui configuration file
    :type file_path: str
    :param webui_http_modules: The required http modules to be added to the file
    :type webui_http_modules: str
    :param webui_httpd_location: The new API endpoint configuration to be added to the file
    :type webui_httpd_location: str
    :param apiname: The name of the new API
    :type apiname: str
    """

    def find_first_last_occurrence(text_lines, search_string):
        first_index = None
        last_index = None

        for index, line in enumerate(text_lines):
            if line.startswith(search_string):
                if first_index is None:
                    first_index = index
                last_index = index

        return first_index, last_index      
    
    def insert_lines_at_index(text_lines, insert_string, index):
        running_index = 0
        for line in insert_string.splitlines():
            tmpidx = index + running_index
            print('Inserting Line %i: %s' % (tmpidx, line.rstrip('\n')))
            text_lines.insert(tmpidx, line + '\n')
            running_index = running_index + 1

    # the Endpoint Config goes before this Block
    block_separator  = "# ================================================="
    Block_identifier = "# Object"

    # Read the file into lines
    with open(file_path, 'r') as file:
        webui_config = file.readlines()

    # add the required modules to the file
    # locate to the modules section and find the end of the LoadModule Block
    _, last_Modules_index = find_first_last_occurrence(webui_config, "LoadModule")
    if last_Modules_index is not None:
            insert_lines_at_index(webui_config, webui_http_modules, last_Modules_index)
    else :
        raise(f"Error: Failed to find Modules section. Bad File?")
    
    # locate to the VirtualHost section
    start_tag   = '{{#WEBUI}}'
    end_tag     = '{{/WEBUI}}'
    found_start_tag = False
    isiAuthIndexes = []
    EndpointIndex = None

    for index, line in enumerate(webui_config):
        if start_tag in line:
            print(f"Found start tag: '{start_tag}' at line: {index}")
            found_start_tag = True
        elif end_tag in line:
            print(f"Found end tag: '{end_tag}' at line: {index}")
            break

        if found_start_tag:
            if "IsiAuthServices" in line:
                isiAuthIndexes.append(index)
                # line = line.rstrip('\n')
                # print(f"Found IsiAuthServices at line: {index}: {line}!")
                webui_config[index] = webui_config[index].rstrip('\n') + ' ' + apiname + '\n'
                print('Changed Line %i: %s to %s!' % (index, line.rstrip('\n').strip(), webui_config[index].rstrip('\n').strip())) 
            elif Block_identifier in line and block_separator in webui_config[index - 1].strip(): 
                line = line.rstrip('\n')
                print(f'Found endpoint index: {index} : {line.strip()}!')
                EndpointIndex = index - 1    
                
                
    if all([isiAuthIndexes, found_start_tag]) :

        # Add the new API endpoint
        if EndpointIndex is not None :
            insert_lines_at_index(webui_config, webui_httpd_location, EndpointIndex)
        else :
            raise(f"Error: '{Block_identifier}' not found.")
        
        # Write out the new file.
        if file_path.endswith('.bak'):
            file_path = file_path.replace('.bak', '.new')

        print(f'Writing new file: {file_path}')
        with open(file_path, 'w') as file:
            for line in webui_config:
                file.write(line)
    else :
        raise("Error: Failed modify webui config. Bad File?")

def isi_for_array(args_list):
    """
    Execute a command on all nodes in the cluster.

    :param args_list: List of command line arguments
    :type args_list: list
    """
    # build the command to run
    cmds = ['isi_for_array']
    cmds.extend(args_list)
    
    # run the command on all nodes
    return subprocess.run(cmds, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def status() :
    """
    Display the status of the custom_api on the cluster.
    """
    
    # Display status message
    sys.stdout.write('Checking status of custom_api...')
    sys.stdout.flush()
    
    # Execute the pgrep command on all nodes
    out = isi_for_array(['-s', 'pgrep',  '-f',  '"python.*custom_api\.py"'])
    
    # Decode the output and split it into lines
    status = out.stdout.decode('utf-8').splitlines()
    
    # Print the status of the custom_api process on each node
    sys.stdout.write('\033[F')
    sys.stdout.write('\n')
    sys.stdout.flush()

    for node in status:
        if 'exited' in node:
            message = node.split(' ')
            print(f"{message[3]}: custom_api.py not running!")
        elif len(node.split(':')) == 2 :
            message = node.split(':')
            try :
                int(message[1].strip())
            except ValueError :
                raise(f"Error: Failed to parse node status output: {node}")
            else :
                print(f'{message[0]}: custom_api.py running with PID: {message[1]}')
        else :
            raise(f"Error: Failed to parse node status output: {node}")

def stop_custom_api():
    """
    Stop the custom_api on the cluster by killing the process.

    This function uses the `isi_for_array` function to execute the `kill` command
    on all nodes in the cluster. The `kill` command is used to send a termination
    signal to the custom_api process identified by its process ID (PID). The PID
    is obtained by searching for the process name in the output of the `ps` command,
    which lists all processes running on the system. The `grep` command is used to
    filter the output to only include lines containing "custom_api.py". The `-v` option
    is used to exclude lines containing "grep" itself. The `cut` command is used to
    extract the fourth column of the output, which contains the PID. The `kill` command
    is then executed on all nodes with the obtained PID.
    """
    # Execute the kill command on all nodes
    print('Stopping custom_api...')
    isi_for_array(['pkill',  '-f',  '"python.*custom_api\.py"'])

def start_custom_api():
    """
    Start the custom_api on the cluster.

    This function executes the 'run.py' script located at '/ifs/data/Isilon_Support/customapi/run.py'.
    This script is responsible for starting the custom_api on all nodes in the cluster.

    """
    # Execute the 'run.py' script to start the custom_api on all nodes
    print('Starting custom_api...')

    command = f'{target_path}/run.py'
    out = isi_for_array(['-s', 'python3', command])

    if out.stderr :
        errors = out.stderr.decode('utf-8').splitlines()
        for error in errors :
            print(error)

    # Decode the output and split it into lines
    status = out.stdout.decode('utf-8').splitlines()

    # Print the status of the custom_api process on each node
    for node in status:
        print(node)

def restart_custom_api():
    stop_custom_api()
    start_custom_api()

def restart_webui():
    """
    Restart the web UI on the cluster.

    This function disables and then enables the web UI service on all nodes in the cluster.
    It uses the `isi` command to execute the operations.
    """
    print('Restarting webui...')
    # Disable the web UI service
    subprocess.run(['isi', 'services', '-a', 'isi_webui', 'disable'])
    
    # Enable the web UI service
    subprocess.run(['isi', 'services', '-a', 'isi_webui', 'enable'])

def install_custom_api(api_port, upgrade=False):
    """
    Install the custom_api on the cluster.

    This function unpacks the 'custom_api.tgz' archive to '/ifs/data/Isilon_Support/customapi'.
    It also adds the startup script 'run.py' to '/etc/mcp/override/crontab' and
    modifies the webui configuration to include the new API endpoint. Finally, it starts
    the custom_api on the cluster and restarts the web UI.
    """

    webui_httpd_location = f"""    # =================================================
    # custom api
    # =================================================
    <Location /{apiname}>
        AuthType Isilon
        IsiAuthName "customapi"
        IsiAuthTypeBasic On
        IsiAuthTypeSessionCookie On
        IsiDisabledZoneAllow Off
        IsiMultiZoneAllow On
        IsiCsrfCheck On
        ProxyPass "http://localhost:{api_port}/"
        ProxyPassReverse "http://localhost:{api_port}/"
        Require valid-user
        ErrorDocument 401 /json/401.json
        Header set Content-Security-Policy "default-src 'none'"
        RequestHeader set X-Remote-User "%{{REMOTE_USER}}s"
        RequestHeader set X-api-location "{apiname}"
        Header unset Server
    </Location>\n
    """

    print('Installing custom API...')
    api_is_installed = os.path.exists(target_path)
    if not api_is_installed or upgrade: 
        # Unpack custom_api.tgz to target_path
        if not api_is_installed :
            print('Unpacking custom_api.tgz to target_path...')
            unpack_archive_with_progress(archive_file, '/ifs/data/Isilon_Support/')

        # Add the startup script "run.py" to /etc/mcp/override/crontab
        print('Adding startup script to /etc/mcp/override/crontab...')
        try :
            with open('/etc/mcp/override/crontab', 'r') as f: 
                lines = f.readlines()
        except FileNotFoundError:
            with open('/etc/mcp/override/crontab', 'x') as f :
                lines = []
        else :
            with open('/etc/mcp/override/crontab', 'a') as f:
                # Iterate over each cronline in webui_crontab
                for cronline in webui_crontab.splitlines():
                    # If the cronline is already present in the file, skip it
                    if any(cronline in line for line in lines):
                        continue
                    else:
                        # Write the cronline to the file
                        f.write(cronline)
                        f.write('\n')
        if os.path.exists(f'{target_path}/webui_httpd.conf.bak'):
            print('A backup of webui_httpd.conf already exists. Not creating a new one.')
        else:
            print('Creating a backup of webui_httpd.conf...')
            # Backup the webui_httpd.conf to {target_path}/webui_httpd.conf.bak
            bkup_path = target_path + '/webui_httpd.conf.bak'
            shutil.copy('/etc/mcp/templates/webui_httpd.conf', bkup_path)

        # Add the webui_httpd_conf to /etc/mcp/templates/webui_httpd.conf before "Object Api"
        
        print('Modifying webui_httpd.conf...')
        modify_webui_config(
            f'{target_path}/webui_httpd.conf.bak',
            webui_http_modules,
            webui_httpd_location,
            apiname,
            api_port=api_port
        )

        print('Distributing changes to all nodes...')
        # Distribute the changes across all nodes in the cluster
        isi_for_array(['cp', '-f', f'{target_path}/webui_httpd.conf.new', '/etc/mcp/templates/webui_httpd.conf'])
        
        print('Distributing control script to all nodes...')
        isi_for_array(['cp', os.path.basename(__file__), '/usr/bin/isi_customapi'])
        isi_for_array(['chmod', '+x', '/usr/bin/isi_customapi'])

        if args.port :
            print('Updating api_config.ini...')
            update_api_config(target_path + '/api_config.ini', 'api_port', f'{api_port}')

        # Start the custom_api on the cluster
        start_custom_api()

        # Restart the webui on the cluster
        restart_webui()
    else :
        print('Custom API seems to be installed already.')

def uninstall_custom_api(delete_from_cluster = False):
    """
    Uninstall the custom_api on the cluster.

    This function removes the startup script "run.py" from /etc/mcp/override/crontab,
    reverts the webui config, stops the custom api on the cluster, restarts the webui
    on the cluster, and removes the custom_api from /ifs/data/Isilon_Support/customapi.
    If delete_from_cluster is True, the custom_api is removed from the filesystem as
    well.

    :param delete_from_cluster: Whether to delete the custom_api from the filesystem
    :type delete_from_cluster: bool
    """
    # Remove the startup script "run.py" from /etc/mcp/override/crontab
    with open('/etc/mcp/override/crontab', 'r') as f:
        lines = f.readlines()
    with open('/etc/mcp/override/crontab', 'w') as f:
        for line in lines :
            if any(line in line for line in webui_crontab.splitlines()):
                continue
            else :
                f.write(line)

    # Revert the webui config:
    isi_for_array(['cp', '-v', f'{target_path}/webui_httpd.conf.bak', '/etc/mcp/templates/webui_httpd.conf'])

    # Stop the custom api on the cluster
    stop_custom_api()

    # Restart the webui on the cluster
    restart_webui() 

    # Remove the custom_api from /ifs/data/Isilon_Support/customapi
    if delete_from_cluster:
        print(f'Removing {target_path}...')
        shutil.rmtree(target_path)   

    # removing myself from /usr/bin
    isi_for_array(['rm', '-f', '/usr/bin/isi_customapi']) 

if __name__ == "__main__":
    # Main parser
    class CustomHelpFormatter(argparse.ArgumentDefaultsHelpFormatter, RawTextHelpFormatter):
        pass

    main_parser = argparse.ArgumentParser(description=f"{argparse.ArgumentParser().prog} {__version__} - Custom API installer for PowerScale\n\nInstalls and controls the custom API serivce on the cluster", epilog=f"For mor details on a command, use:\n\t{argparse.ArgumentParser().prog} <command> --help", formatter_class=CustomHelpFormatter)

    subparsers = main_parser.add_subparsers(dest='command', title='Commands', metavar='', help='')

    parser_install      = subparsers.add_parser('install',   help="Install the custom API" ) 
    parser_uninstall    = subparsers.add_parser('remove',    help="Uninstall the custom API" )
    parser_start        = subparsers.add_parser('start',     help="Start the custom API" )
    parser_stop         = subparsers.add_parser('stop',      help="Stop the custom API" )
    parser_restart      = subparsers.add_parser('restart',   help="Restart the custom API" )
    parser_status       = subparsers.add_parser('status',    help="Check the status of the custom API" )

    parser_install.add_argument("--name", dest='name', help="Set the endpoint name for the custom API", default=apiname )
    parser_install.add_argument('--port', dest='port', help='Internal API Port.', default='8000')
    parser_install.add_argument("--post-upgrade", action='store_true', dest='postUpgrade', help="Reinstall the custom API after upgrade" )

    parser_uninstall.add_argument("--delete-from-ifs", action='store_true', dest='deleteFromIFS', help="Delete the custom API files from OneFS" )
    
    args = main_parser.parse_args()

    if args.command == 'install' :      
        # Install the custom API
        try :
            api_port = int(args.port)
        except ValueError:
            print(f'Invalid port: {args.port}')
            sys.exit(1)
        apiname = args.name
        install_custom_api(api_port, args.postUpgrade)            
    elif args.command == 'remove' :     
        # Uninstall the custom API
        uninstall_custom_api(args.deleteFromIFS)
    elif args.command == 'start' :      
        # Start the custom API
        start_custom_api()
    elif args.command == 'stop' :       
        # Stop the custom API
        stop_custom_api()
    elif args.command == 'restart' :    
        # Restart the custom API
        restart_custom_api()
    elif args.command == 'status' :     
        # Check the status of the custom API
        status()
    else :
        main_parser.print_help()