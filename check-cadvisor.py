#!/usr/bin/python

import sys, requests, argparse, json

checkName = "check-cadvisor.py"
checkVersion = "0.3.0"

#CHANGE SUMMARY
#PERFORMANCE DATA REFCATOR
#REMOVED STARTTIME, CMD, STATUS AS THESE VALUES ARE STRINGS 
#CHANGE TO UNKNOWN MESSAGES FORMAT
#TYPO CORRECTIONS

#GET LIST OF ALL CONTAINERS SND CGROUP_PATHS
def getContainerList(args):
    url = (args.target+":"+args.port+"/api/"+args.version+"/summary?type=docker&recursive=true") 
    
    #GET THE LIST OF PROCESSES
    r = requests.get(url=url)

    # DEBUG OUT
    if args.debug:
        #CADVISOR CONTAINER LIST AS CGROUPS
        print("CONTAINERS")
        print(url)
        print(r.json())
    
    if r.status_code != 200:
        #EXIT WITH UNKNOWN
        checkStateCode = 3
        msg = "UNABLE TO RETRIEVE CONTAINER LIST FROM CADVISOR"
        checkExit(checkStateCode, msg)
    else:
        #RETURN LIST OF PROCESSES
        return r  

#GET SPEC DATA FOR EACH CONTAINER AND SEARCH FOR NAME VIA ALIAS
def getContainerSpecData(args, clist):
    #INT AS BOOLEAN
    match = 0
    
    #CGROUP_PATH
    cgp = ""
    
    #MAKE IT JSON SO WE CAN PARSE EASIER
    clistj = clist.json()
    
    #LOOP THROUGH LIST OF CONTAINERS AND GET SPEC DATA
    for k in clistj.items():
        #FIRST ITEM IS ALWAYS CGROUP_PATH
        cgp = k[0]

        #GET SPEC MATCHING CGROUP_PATH
        cspecdata = getContainerStats(args,cgp)
        cspecdataj = cspecdata.json()

        #LIST OF ALIASES FOR EACH CONTAINER
        aliaslist = cspecdataj[cgp]['spec']['aliases']
        
        if args.debug:
            print("CGROUP_PATH")
            print (cgp)
            print("ALIAS LIST")
            print(aliaslist)

        #LOOK FOR MATCH IN EACH LIST OF ALIASES
        for a in aliaslist:
            if a == args.container:
                match = 1
                return match, cgp
    
    #RETURN INT AS BOOLEAN FOR MATCH AND GCP
    return match,cgp


#GET THE PROCESS LIST FROM CADVISOR FOR CGROUP
def getDockerPs(args, cgp):
    url = (args.target+":"+args.port+"/api/"+args.version+"/ps"+cgp)
    
    #GET THE LIST OF PROCESSES
    r = requests.get(url=url)

    # DEBUG OUT
    if args.debug:
        #CADVISOR URL WITH CGROUP
        print("DOCKER CGROUP PROCESS URL")
        print(url)
        
        #PROCESS DATA
        #COULD PROVIDE LOTS OF DATA USE AT OWN RISK
        #print("CADVISOR CGROUP PROCESS LIST")
        #print(r.json())
    
    if r.status_code != 200:
        #STATE UNKNOWN
        checkStateCode = 3
        msg = "UNABLE TO RETRIEVE PROCESS LIST FROM CADVISOR"
        
        #EXIT CHECK
        checkExit(checkStateCode, msg)
    else:
        #RETURN LIST OF PROCESSES
        return r

#DOCKER CONTAINER STATS
def getContainerStats(args,cgp):

    #API URL FOR THE CGROUP STATS
    url = (args.target+":"+args.port+"/api/"+args.version+"/stats"+cgp)
    
    #HTTP GET THE CONTAINER STATS
    r = requests.get(url=url)

    if args.debug:
        print("CADVISOR URL")
        print(url)
        #LOTS OF DATA USE AT OWN RISK
        #print("REQUEST JSON")
        #print(r.json())
    
    #REQUEST OTHER THAN 200 INDICATE PROBLEMS WITH CONNECTIVITY
    if r.status_code != 200:
        #STATE UNKNOWN
        checkStateCode = 3
        msg = "UNABLE TO RETRIEVE STATS FOR CONTAINER ("+args.container+") FROM CADVISOR"
        
        #EXIT CHECK
        checkExit(checkStateCode,msg)
    else:
        #RETURN CONTAINER STATS
        return r

def getDockerSats(docker_ps_out,cgp):
    #GET THE JSON
    dpsj = docker_ps_out.json()
    
    #TOTAL PROCESS COUNT
    tp = 1
    
    #CONTAINER PROCESS COUNT
    pc = 0
    
    # CONTAINER RESULTS DICT
    c = {}

    #LOOP THROUGH PROCESS LIST RESULTS FROM DOCKER HOST FOR OUR CONTAINER
    for k in dpsj:
        # DATA FOR DICT
        cmd = k['cmd']
        status = k['status'] 
        cgroup = k['cgroup_path']
        pid = k['pid']
        parent_pid = k['parent_pid']
        user = k['user']
        start_time = k['start_time']
        running_time = k['running_time']
        percent_cpu = k['percent_cpu']
        percent_mem = k['percent_mem']
        running_time = k['running_time']
            
        #RESULTS FOR SINGLE PROCESS
        st = ({'command':cmd, 'status':status, 'cgroup_path':cgroup, 'user':user, 'pid':pid, 'parent_pid':parent_pid, 'percent_cpu':percent_cpu, 'percent_mem':percent_mem, 'start_time':start_time, 'running_time':running_time})
        
        #ADD PROCESS RESULTS
        c.update({pc:{'stats':st}})
        
        #INCREMENT CGROUP_PATH ASSOCIATED PROCESS COUNT
        pc += 1

        # INCREMENT TOTAL PROCESS COUNT
        tp += 1

    #DEDUG OUT
    if args.debug:
        #CGROUP ASSOCIATED PROCESS/S
        print("CGROUP ASSOCIATED PROCESS/S")
        print (c)

    # NO PROCESS NO CONTAINER THROW A CRITICAL ALERT 
    if pc == 0:
        msg = "Found ("+str(pc)+") process/processes out of ("+str(tp)+") matching the CGROUP_PATH ("+cgp+")."
        checkStateCode = 2
        #EXIT CHECK
        checkExit(checkStateCode, msg)
    else:
        #RETURN CONTAINER PROCESS DATA
        return c

#GET PROCESS PERFDATA
def getCheckPerfdata(docker_ps_data):
    #DEALING WITH THE POSIBILITY OF MULTIPLE PROCESSES
    psct = 0
    for k in docker_ps_data.keys():
        psc = k
        pstate = docker_ps_data[psc]['stats']['status']

        if pstate != "":
            psct += 1

    #TOTALS
    p_cpu_total = 0
    p_mem_total = 0

    #PERFDATA USE NAGIOS OUT FORMAT
    perfdata = "|"

    if psct > 0:
        #HAVE TO DEAL WITH MULTIPLE PROCESSES SO JUST MAKE IT A DICT
        for pk in docker_ps_data.keys():
            psc = pk
            
            #UPDATE TOTALS
            p_cpu_total += docker_ps_data[pk]['stats']['percent_cpu']
            p_mem_total += docker_ps_data[pk]['stats']['percent_mem']

            
            #PREFIX TO DENOTE PER PROCESS 
            prefix = "process-"+str(pk)+"-"

            #PER PROCESS PID
            perfdata += prefix+"pid="+str( docker_ps_data[pk]['stats']['pid'])+"; "

            #PER PROCESS PARENT PID
            perfdata += prefix+"parent-pid="+str( docker_ps_data[pk]['stats']['parent_pid'])+"; "
            
            #PER PROCESS RUNNING TIME
            perfdata += prefix+"running-time="+str( docker_ps_data[pk]['stats']['running_time'])+"; "

            #PER PROCESS CPU
            perfdata += prefix+"cpu="+str( docker_ps_data[pk]['stats']['percent_cpu'])+"; "

            #PER PROCESS MEM
            perfdata += prefix+"mem="+str( docker_ps_data[pk]['stats']['percent_mem'])+"; "

        #ADD THE SUM TOTALS TO THE PERFDATA
        perfdata += "total-process-count="+str(psct)+"; "
        perfdata += "total-cpu="+str(p_cpu_total)+"; "
        perfdata += "total-mem="+str(p_mem_total)+"; "

    if args.debug:
        #PERFDATA
        print("PERFDATA")
        print(perfdata)
    
    return perfdata        

def checkSateFromCode(i):
    switcher = {
        0: "OK",
        1: "WARNING",
        2: "CRITICAL",
        3: "UNKNOWN"
    }

    #GIVE THE STATE BACK
    return switcher.get(i)

#CHECK EXIT
def checkExit(checkStateCode,msg):
    #GET qCHECK STATE FROM CHECK STATE CODE
    checkState = checkSateFromCode(checkStateCode)
    
    #BUILD THE CHECK OUTPUT
    check_out = checkState+": "+msg 
    
    #DEBUG OUT
    if args.debug:
        #STATE CODE
        print("CHECK EXIT STATE CODE")
        print(str(checkStateCode))

        #CHECK EXIT STATE
        print("CHECK EXIT STATE")
        print(checkState)

        #MESSAGE CONTENT
        print("CHECK MESSAGE CONTENT")
        print(msg)    


    #PRINT THE CHECK MESSAGE
    print(check_out)

    #EXIT WITH STATECODE
    sys.exit(checkStateCode)

# MAIN
if __name__ == "__main__":
    
    #GET COMMAND INPUT
    cinput = argparse.ArgumentParser(prog=checkName+"v:"+checkVersion, formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    cinput.add_argument(
        "-t", "--target",
        required=True,
        default=None,
        help="String(URL/IP): The URL/IP of the Docker Host of the target cadvisor container."
    )
    cinput.add_argument(
        "-p", "--port",
        required=True,
        default=None,
        help="INT(PORT): The exposed tcp port for the cadvisor container on the Docker Host."
    )
    cinput.add_argument(
        "-v", "--version",
        required=True,
        default="v2.1",
        help="String(vMajor.Minor): The cadvisor API version to query."
    )
    cinput.add_argument(
        "-n", "--container",
        required=True,
        default=None,
        help="String: The name of the container you want to query for."
    )
    cinput.add_argument(
        "--perfdata",
        required=False,
        action="store_true",
        help="Boolean: When set, return performance data as past of check output."
    )
    cinput.add_argument(
        "-d", "--debug",
        required=False,
        action="store_true",
        help="Boolean: When set, enable the command debug output."
    )

# BUILD ARGS ARRAY
args = cinput.parse_args()

#GET LIST OF CONTAINER CGROUPS FROM CADVISOR
clist = getContainerList(args)

#SEARCH FOR ALIAS
hasContainer = getContainerSpecData(args, clist)

#DEBUG OUT
if args.debug:
    #HASCONTAINER
    print("HAS CONTAINER VALUE")
    print(hasContainer)

if hasContainer[0] == 1:
    #CGP FROM CONTAINER LIST
    cgp = hasContainer[1]
    
    #GET CADVISOR KNOWN PROCESS LIST FOR THE CGROUP_PATH
    docker_ps_out = getDockerPs(args,cgp)
    docker_ps_data = getDockerSats(docker_ps_out,cgp)

    #PROCESS COUNT
    pscnt = 0
    for ps in docker_ps_data.keys():
        pscnt += 1
    
    #DEBUG OUT

    if pscnt > 0:
        #OUTPUT MSG
        checkStateCode = 0
        msg = "CONTAINER UP, FOUND ("+str(pscnt)+") TOTAL PROCESS/S FOR ("+args.container+") "    

        #GET PERFDATA
        if args.perfdata:
            perfdata = getCheckPerfdata(docker_ps_data)
            msg += perfdata
    else:
        #OUTPUT MSG
        checkStateCode = 2
        msg = "FOUND ("+str(pscnt)+") TOTAL PROCESS/S FOR ("+args.container+") "

    #EXIT CHECK
    checkExit(checkStateCode, msg)
else:
    #NO CONTAINER SO EXIT WITH CRITICAL
    checkStateCode = 2
    msg = "NO RUNNING CONTAINER FOUND MATCHING ("+args.container+")."
    
    #EXIT CHECK
    checkExit(checkStateCode,msg)
