""" enumerates the ips and enriches data by providing location data, whois
data and more
"""

import re
from json import loads, dumps
from time import sleep
import subprocess
import ipaddress
import requests
from ratelimit import limits
import shodan
import threatcrowd
from ipwhois import IPWhois

# Read in API keys
with open(".env") as env:
	KEYS = loads(env.read())
shodan_api = shodan.Shodan(KEYS["shodan"])
urlscan_api = KEYS["urlscan"]

def prettyJson(json):
	""" format a python dict (json object) """
	return dumps(json, indent="  ")

def wSubP(args):
	"""wrap the subprocess command to reduce duplication

	Args:
		args (list): list of args

	Returns:
		CompletedProcess: process results
	"""
	return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def getDomain(ipAddr):
	"""return the corrosponding domain from the IP passed into the function

	Args:
		ipAddr (string): ip address to scan

	Returns:
		string: the domain
	"""

	domainStr = wSubP(["host", ipAddr]).stdout.decode("utf-8")

	if "not found" in domainStr:
		return ""

	domain = re.findall(r"pointer (.*?)$",
	domainStr, re.MULTILINE)
	domain = domain[0][:-1]
	return domain

def isUp(ipAddr):
	"""ping the ip or domain to determine if it is currently up

	Args:
		ipAddr (string): ip address to scan

	Returns:
		string: string result
	"""
	pingResults = wSubP(["ping", "-c", "3", ipAddr])
	result = re.findall(r", (.) received",
	pingResults.stdout.decode("utf-8"))[0] in ("2", "3")
	return ipAddr + " is " + ("up" if result else "down")


def whoisQuery(ipAddr):
	"""return whois results

	Args:
		ipAddr (string): ip address to scan

	Returns:
		string string result
	"""
	d = IPWhois(ipAddr)

	return prettyJson(d.lookup_whois())


def dig(domain):
	"""return dig results

	Args:
		domain (string): domain to scan

	Returns:
		string: string result
	"""
	if domain == "":
		return "\"dig scan failed\""

	digResults = subprocess.getoutput("dig a "+domain+" +nocomments +noquestion +noauthority +noadditional +nostats  | awk '{if (NR>3){print}}'| tr -s '\t' | jq -R 'split(\"\t\") |{Name:.[0],TTL:.[1],Class:.[2],Type:.[3],IpAddress:.[4]}' | jq --slurp .")

	return digResults

@limits(calls=1, period=5)
def ipvigilante(ipAddr):
	""" ipvigilante api ip: target ip
	
	Args:
		ipAddr (String): ip address to scan
		
	Returns:
		string: string result
	"""
	location = requests.get("https://ipvigilante.com/" + ipAddr).json()
	if location["status"] == "success":
		return prettyJson(location["data"])
	return prettyJson({"results" : "Lookup Failed"})

@limits(calls=1, period=10)
def shodanApi(ipAddr):
	""" shodan api 

	Args:
		ipAddr (String): ip address to scan
		
	Returns:
		string: string result	
	"""
	try:
		host = shodan_api.host(ipAddr)
	except shodan.exception.APIError as err:
		return prettyJson({"results" :"API Error: {0}".format(err)})
	for element in host["data"]: # get rid of the http nonsense as this is just
		if "http" in element: # a bunch of html
			element.pop("http")
	return prettyJson({"results" :host["data"][0]})


@limits(calls=1, period=2)
def urlscan(targetUrl, public=False):
	""" urlscan api 
	Args:
		targetUrl (String): url to scan
	
	Returns:
		string: string result
	"""
	headers = {'Content-Type': 'application/json', 'API-Key': urlscan_api, }
	if not public:
		data = '{"url": "%s"}' % targetUrl
	else:
		data = '{"url": "%s", "public": "on"}' % targetUrl

	resp = requests.post('https://urlscan.io/api/v1/scan/', headers=headers,
	data=data).json()
	if resp["message"] == "Submission successful":
		return prettyJson({"message": resp["message"], "result" : resp["result"]})
	return prettyJson({"message": resp["message"], "result" : "Error Status " + str(resp["status"])})


@limits(calls=1, period=10)
def threatcrowdApi(ipAddr, domain):
	""" threatcrowd api 

	Args:
		ipAddr (String): ip address to scan
		domain (String): domain to scan
		
	Returns:
		string: string result
	"""
	tempDict = {}
	ipReport = threatcrowd.ip_report(ipAddr)

	if ipReport["response_code"] != "0":
		tempDict["IP_Report"] = ipReport["permalink"]
	else:
		tempDict["IP_Report"] = "No Response on IP: "+ ipAddr

	sleep(10)
	domainReport = threatcrowd.domain_report(domain)
	if domainReport["response_code"] != "0":
		tempDict["Domain_Report"] = domainReport["permalink"]
	else:
		tempDict["Domain_Report"] = "No Response on Domain: "+ domain

	return prettyJson(tempDict)

def run(ipAddress):
	"""main entry point from calling program

	Args:
		ipAddress (string): the ip address to run through the various scans

	Returns:
		string: json formatted string to be written to a file
	"""
	retJSON = "{"

	domain = getDomain(ipAddress)

	print(domain)

	retJSON += "\n\"isup\": \"" + isUp(ipAddress) + "\","

	retJSON += "\n\"dig\": " + dig(domain) + ","

	retJSON  += "\n\"whois\": "+ whoisQuery(ipAddress) + ","

	retJSON += "\n\"ipvigilante\": " + ipvigilante(ipAddress) + ","

	retJSON += "\n\"shodan\": " + shodanApi(ipAddress) + ","

	retJSON += "\n\"urlscan\": " + urlscan(domain) + ","

	retJSON += "\n\"threatcrowd\": " + threatcrowdApi(ipAddress, domain) 

	retJSON += "\n}"
	# https://pulsedive.com/api/

	# https://www.hybrid-analysis.com/docs/api/v2

	return prettyJson(loads(retJSON))
