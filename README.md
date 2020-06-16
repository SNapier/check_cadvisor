# check_cadvisor
Python based script used to monittor docker containers in conjunction with Google's cadvisor.

# Requires

## Python3
Installed and available in the system path
https://www.python.org/downloads/

## Python3 Modules
Requests
https://requests.readthedocs.io/en/master/

## Cadvisor
Cadvisor need be installed and operational on the Docker host
https://github.com/google/cadvisor

# Script Usage
## Permissions
chmod +x chech-cadvisor.py

## Execution
./check-cadvisor.py  

### Required Input
-t/--target "http://fqdn or ip"
-p/--port "external port for cadvisor"
-n/--container "container name to monitor"
-v/--version "cadvisor API version"

### Optional Flags
--perfdata "If present will return perfdata for processes with 0/OK state."
-d "If present will echo the debug out for functions in script."
