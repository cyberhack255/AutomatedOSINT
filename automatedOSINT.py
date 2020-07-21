import os
import sys
import IPScan
import ipaddress
import optparse
from tqdm import tqdm
import time
from math import ceil
from json import dumps


def options():
    options = []
    options.append(optparse.make_option('--ip-address', '-i', dest='ipaddress', help='single ip address to scan', default=None))
    options.append(optparse.make_option('--ip-file', '-f', dest='ipfile', help='file containing ip addresses', default=None))
    options.append(optparse.make_option('--out-dir', '-o', dest='outdir', help='directory to write logfiles to', default='IPLogFiles/'))
    return options


def v4orv6(ip):
    """distinguishes between IPv4 and IPv6 addresses and creates the appropriate filename
        
        Args:
            ip - the IP which to convert
        
        Returns:
            String - the appropriate filename which to save the file under
    """
    try:
        ipaddress.IPv4Address(ip)
        octets = ip.split(".")
        return "ip4-"+octets[0]+"-"+octets[1]+"-"+octets[2]+"-"+octets[3]+".json"
    except ipaddress.AddressValueError:
        hextets = ip.split(":")
        newHextets = []
        print(hextets)
        for h in range(len(hextets)):
            if hextets[h] != "":
                newHextets.append(hextets[h].zfill(4))
            else:
                no = 8-(len(hextets)-1)
                for x in range(no):
                    newHextets.append("0000")
                print(newHextets)
        return "ip6-" + newHextets[0]+"-"+ newHextets[1]+"-"+ newHextets[2]+"-"+ newHextets[3]+"-"+ newHextets[4]+"-"+ newHextets[5]+"-"+ newHextets[6]+"-"+ newHextets[7]+".json"


def prettyJson(json):
	""" format a python dict (json object) """
	return dumps(json, indent="  ")


def main(options):
    """ Collects the IP addresses given to it and runs them through IPScan dumping the results in logfiles

    Args:
        options - the parsed options provided by optparse
    
    Returns:
        N/A
    """

    SAVEFILE = options.outdir.strip("/")+"/"


    pbar = tqdm(total=100, dynamic_ncols=True,leave=True ,bar_format='{percentage:3.0f}% |{bar:40}| {desc}')
       
    IPList = []
    if options.ipfile:
        with open(options.ipfile, "r") as f:
            for line in f:
                IPList.append(line.replace("\n", ""))
    else:
        IPList.append(options.ipaddress)
    pastIPs = os.listdir(SAVEFILE)
    for ip in IPList:
        valid = True
        try:
            ipaddress.ip_address(ip)
        except:
            pbar.set_description_str("IP Address: "+ip+" is not valid")
            time.sleep(2)
            pbar.update(ceil(100/len(IPList)))
            valid = False
        if valid:
            formatIP = v4orv6(ip)
            if formatIP not in pastIPs:
                pbar.set_description_str("Processing IP Address: " + ip)
                with open(SAVEFILE+formatIP, "w+") as f:
                    tempStr = IPScan.run(ip)
                    f.write(tempStr)
                    pbar.set_description_str("IP Address: "+ ip +" has been scanned")
                    pbar.update(ceil(100/len(IPList)))
                    time.sleep(2)
            else:
                pbar.set_description_str("IP Address: "+ ip +" already been scanned")
                time.sleep(2)
                pbar.update(ceil(100/len(IPList)))
                
    pbar.n = 100
    pbar.close()


if __name__ == "__main__":

    usage_str = "usage: %prog [options] \n Gather OSINT data on ip addresses" 
    parser = optparse.OptionParser(usage=usage_str, option_list=options())
    options, args = parser.parse_args()

    if not options.ipaddress and not options.ipfile:
        print("You need to specify an IP address or file containing IP addresses to scan")
        sys.exit()

    if options.ipfile and not os.path.isfile(options.ipfile):
        print("IP address file does not exist: " + options.ipfile)
        sys.exit()

    if options.outdir and not os.path.isdir(options.outdir) and options.outdir != "IPLogFiles/":
        print("Out Directory does not exist: "+ options.outdir+"\nwould you like to create it (Y/n): ", end="")
        y_or_no = input().lower()
        if y_or_no == "n":
            sys.exit()
        else:
            os.system("mkdir -p " + options.outdir)
    else:
        os.system("mkdir -p IPLogFiles")

    main(options)