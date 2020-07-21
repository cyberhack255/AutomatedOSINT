"""Calls getIncidentData and IPScan and dumps the results in log files

getIncidentData gets incidents from the past two hours and returns a dictionary
of the event and associated ips

IPScan enumerates the ips and enriches data by providing location data, whois
data and more
"""
import os
import IPScan
from tqdm import tqdm
import time
from math import ceil
from json import dumps

def prettyJson(json):
	""" format a python dict (json object) """
	return dumps(json, indent="  ")

pbar = tqdm(total=100, dynamic_ncols=True,bar_format='{percentage:3.0f}% |{bar:40}| {desc}')
SAVEFOLDER = "IPLogFiles/"
IPList = []
os.system("mkdir -p "+SAVEFOLDER)
with open("IPs.txt", "r") as ipFile:
    for line in ipFile:
        IPList.append(line.replace("\n", ""))
pastIPs = os.listdir(SAVEFOLDER)
for ip in IPList:
    octets = ip.split(".")
    formatIP = "ip4-"+octets[0]+"-"+octets[1]+"-"+octets[2]+"-"+octets[3]+".json"
    if formatIP not in pastIPs:
        pbar.set_description_str("Processing IP Address: " + ip)
        with open(SAVEFOLDER+formatIP, "w+") as f:
            tempStr = IPScan.run(ip)
            f.write(tempStr)
            pbar.set_description_str("IP Address: "+ ip +" has been scanned")
            pbar.update(ceil(100/len(IPList)))
            time.sleep(2)
    else:
        pbar.set_description_str("IP Address: "+ ip +" already been scanned")
        time.sleep(2)
        pbar.update(ceil(100/len(IPList)))
pbar.close()
