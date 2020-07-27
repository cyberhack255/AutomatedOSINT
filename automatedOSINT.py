import os
import sys
import IPScan
import ipaddress
import argparse
from tqdm import tqdm
import time
from math import ceil
from json import dumps


BANNER = """\033[93m
**************************************************************************************
*              _                        _           _ _____ _____ _____ _   _ _____  *
*             | |                      | |         | |  _  /  ___|_   _| \ | |_   _| *
*   __ _ _   _| |_ ___  _ __ ___   __ _| |_ ___  __| | | | \ `--.  | | |  \| | | |   *
*  / _` | | | | __/ _ \| '_ ` _ \ / _` | __/ _ \/ _` | | | |`--. \ | | | . ` | | |   *
* | (_| | |_| | || (_) | | | | | | (_| | ||  __/ (_| \ \_/ /\__/ /_| |_| |\  | | |   *
*  \__,_|\__,_|\__\___/|_| |_| |_|\__,_|\__\___|\__,_|\___/\____/ \___/\_| \_/ \_/   *
*                                                                                    *
*  automatedOSINT v1.0                                                               *
*  Coded by Joe Wrieden                                                              *
*  github.com/JoeWrieden                                                             *
**************************************************************************************
\033[0m""" 


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


def main(args):
    """ Collects the IP addresses given to it and runs them through IPScan dumping the results in logfiles

    Args:
        args - the parsed args provided by argparse

    Returns:
        N/A
    """

    SAVEFILE = args.outdir.strip("/")+"/"


    pbar = tqdm(total=100, dynamic_ncols=True,leave=True ,bar_format='{percentage:3.0f}% |{bar:40}| {desc}')

    IPList = []
    if args.ipfile:
        with open(args.ipfile, "r") as f:
            for line in f:
                IPList.append(line.replace("\n", ""))
    else:
        IPList.append(args.ipaddress)
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
                    time.sleep(2)
                    pbar.update(ceil(100/len(IPList)))
            else:
                pbar.set_description_str("IP Address: "+ ip +" already been scanned")
                time.sleep(2)
                pbar.update(ceil(100/len(IPList)))

    pbar.n = 100
    pbar.close()


if __name__ == "__main__":

    print(BANNER)


    parser = argparse.ArgumentParser(
    description='Gather OSINT data on IP addresses')
    parser.add_argument("-f", "--ip-file", dest="ipfile",
                        help="Path to a file, directory or ZIP archive containing IP addresses to scan.")
    parser.add_argument("-i",  "--ip-address", dest="ipaddress",
                        help="A single ip address to scan")
    parser.add_argument("-o",  "--outfile", dest="outdir",
                        help="A Directory to wirte the logfiles from the completed scans to", default="IPLogFiles/")

    args = parser.parse_args()

    if not args.ipaddress and not args.ipfile:
        parser.print_help()
        print("\nYou need to specify an IP address or file containing IP addresses to scan")
        sys.exit()

    if args.ipfile and not os.path.isfile(args.ipfile):
        print("IP address file does not exist: " + args.ipfile)
        sys.exit()

    if args.outdir and not os.path.isdir(args.outdir) and args.outdir != "IPLogFiles/":
        print("Out Directory does not exist: "+ args.outdir+"\nwould you like to create it (Y/n): ", end="")
        y_or_no = input().lower()
        if y_or_no == "n":
            sys.exit()
        else:
            os.system("mkdir -p " + args.outdir)
    else:
        os.system("mkdir -p IPLogFiles")

    main(args)
