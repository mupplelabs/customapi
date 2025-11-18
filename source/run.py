#!/usr/bin/env python
import subprocess
import os
import sys
import socket

silent = False 

if len(sys.argv) > 1 :
    if 'silent' in sys.argv :
        silent = True
    else :
        print('Usage: run.py [silent]')
        exit()         

# Get the PID of a running Python process matching the name of our API script
# If no matching PID is found, start a new instance of the API script  

try: 
    # Use the 'pgrep' command to find matching PIDs
    proc_list = subprocess.check_output(['pgrep', '-f', 'python.*custom_api\.py'])
except subprocess.CalledProcessError:
    # If no matching PIDs are found, create a log file if it doesn't already exist
    logdir = f'/ifs/data/Isilon_Support/customapi/logs/'
    logPath = f'{logdir}{socket.gethostname()}.out'
    if not os.path.exists(logdir) :
        os.mkdir(logdir)
    if not os.path.exists(logPath) :
        with open(logPath, 'w'):
            pass
    # Open the log file in append mode
    try :
        logfd = open(logPath, 'a')
    except IOError:
        if not silent :
            print(f'Failed to open log file: {logPath}')
        exit()
    # Start a new instance of our API script and redirect its output to the log file
    process = subprocess.Popen(['python3', '/ifs/data/Isilon_Support/customapi/bin/custom_api.py'], stdout=logfd, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, start_new_session=True)
    # Check if the process started successfully
    status = f'custom api started with PID: {process.pid}' if process.poll() is None else f'custom api failed to start with PID: {process.pid}'
    if not silent :
        print(status)
else :
    if not silent :
        # If a matching PID is found, print the PID to the console
        myPID = proc_list.decode('utf-8').rstrip('\n')
        print(f'custom_api already running with PID: {myPID}')
