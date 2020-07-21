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
import whois
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

def getIpAndDomain(ipOrDomain):
	"""return the ip and the domain from a value that is either an ip or a
	domain

	Args:
		ipOrDomain (string): ip address or a domain

	Returns:
		Tuple(string, string): ip address and domain
	"""
	isIp = True
	ipaddress.ip_address(ipOrDomain)
	if isIp:
		ipAddress = ipOrDomain
		domain = re.findall(r"pointer (.*?)$",
		wSubP(["host", ipOrDomain]).stdout.decode("utf-8"), re.MULTILINE)
		if len(domain) > 0:
			domain = domain[0][:-1]
		else:
			domain = ""
	else:
		domain = ipOrDomain
		ipAddress = re.findall(r"address (.*?)$",
		wSubP(["host", ipOrDomain]).stdout.decode("utf-8"), re.MULTILINE)[0]

	return ipAddress, domain

def isUp(ipOrDomain):
	"""ping the ip or domain to determine if it is currently up

	Args:
		ipOrDomain (string): ip address or a domain

	Returns:
		string: string result
	"""
	pingResults = wSubP(["ping", "-c", "3", ipOrDomain])
	result = re.findall(r", (.) received",
	pingResults.stdout.decode("utf-8"))[0] in ("2", "3")
	return ipOrDomain + " is " + ("up" if result else "down")


def whoisQuery(ipOrDomain):
	d = IPWhois(ipOrDomain)

	return prettyJson(d.lookup_whois())


def dig(ipOrDomain):
	"""return dig results

	Args:
		ipOrDomain (string): ip address or a domain

	Returns:
		string: string result
	"""
	digResults = wSubP(["host", "-a", ipOrDomain])
	digRes = re.findall(r"ANSWER SECTION:(.*?)Received",
	digResults.stdout.decode("utf-8"),
	re.DOTALL)
	if len(digRes) > 0:
		tempStr = digRes[0].replace("\n", "").replace("\t", "    ")
	else:
		tempStr = "Dig scan failed"
	return tempStr

@limits(calls=1, period=5)
def ipvigilante(ipAddr):
	""" ipvigilante api ip: target ip"""
	location = requests.get("https://ipvigilante.com/" + ipAddr).json()
	if location["status"] == "success":
		return prettyJson(location["data"])
	return prettyJson({"results" : "Lookup Failed"})

@limits(calls=1, period=10)
def shodanApi(ipAddr):
	""" shodan api """
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
	""" urlscan api """
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
	""" threatcrowd api """
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

def run(ipOrDomain):
	"""main entry point from calling program

	Args:
		ipOrDomain (string): ip address or a domain

	Returns:
		string: string result
	"""
	retJSON = "{"
	# Get ip and domain
	ipAddress, domain = getIpAndDomain(ipOrDomain)

	# linux/ unix functions in place of the folowing resources
	# https://centralops.net/co/
	# https://www.ipvoid.com/
	# https://whois.domaintools.com/
	retJSON += "\n\"isup\": \"" + isUp(ipOrDomain) + "\","
	retJSON += "\n\"dig\": \""+ dig(ipOrDomain) + "\","

	retJSON  += "\n\"whois\": "+ whoisQuery(ipOrDomain) + ","


	# https://www.ipvigilante.com/api-developer-docs/
	retJSON += "\n\"ipvigilante\": " + ipvigilante(ipAddress) + ","

	# https://shodan.readthedocs.io/en/latest/tutorial.html#installation
	retJSON += "\n\"shodan\": " + shodanApi(ipAddress) + ","

	# https://urlscan.io/about-api/
	retJSON += "\n\"urlscan\": " + urlscan(domain) + ","
	#https://www.threatcrowd.org/
	#https://github.com/AlienVault-OTX/ApiV2
	'''
	Limits
	Please limit all requests to no more than one request every ten seconds.

	Brief bursts of requests that exceed this (eg; if you're using Maltego to
	enrich a large set of indicators) are ok so long as they don't significantly
	impact the performance of the server.

	If you require faster access than this please drop me a line at
	threatcrowd@gmail.com and I can raise it - the broad principal is that faster
	access is fine, so long as it doesn't impact the performance for other users.
	'''

	retJSON += "\n\"threatcrowd\": " + threatcrowdApi(ipAddress, domain) 

	retJSON += "\n}"
	# https://pulsedive.com/api/

	# https://www.hybrid-analysis.com/docs/api/v2

	return prettyJson(loads(retJSON))
