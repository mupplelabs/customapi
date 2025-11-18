# build the package

### 1. Setup the folder structure:
```
# mkdir -p /ifs/data/Isilon_Support/customapi/bin/
```
### 2. Get Flask libraries and dependencies:
```
# python -m pip install Flask --target /ifs/data/Isilon_Support/customapi/bin/
```
### 3. Add the custom api base scripts to ```/ifs/data/Isilon_Support/customapi/bin/```
These are the files:
- custom_api.py
- isi_authorizer.py
- isi_s3_describe.py

### 3. Add the management script and config to ```/ifs/data/Isilon_Support/customapi/```
Copy api_config.ini and run.py to ```/ifs/data/Isilon_Support/customapi/```

### 4. Pack the customapi folder with tar:
```
# cd /ifs/data/Isilon_Support/
# tar cvfz custom_api.tgz customapi/
```
### 5. Distribute the following files:
- installer.py
- README.md
- custom_api.tgz

# install without distributing.

Instead of steps 4 and 5 above copy the installer.py to ```/ifs/data/Isilon_Support```</br>
And execute the installer:
```
# python /ifs/data/Isilon_Support/installer.py install --post-upgrade
```
Now the api should be installed and up and running.
Control state with:
```
# isi_customapi status
```
Output as follows:
```
hemingway-1: custom_api.py running with PID:  96626
hemingway-2: custom_api.py running with PID:  89627
hemingway-3: custom_api.py running with PID:  76379
hemingway-4: custom_api.py running with PID:  53789
```
Access the API and test. 

REST in peace :-)