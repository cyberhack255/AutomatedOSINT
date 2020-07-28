# AutomatedOSINT

AutomatedOSINT is a tool used to automate the collection of Open Source Intelligence data on IP addresses. The program will  run the IP address found through a series of OSINT API's and then create a JSON file containing the output of the scans which can then be easily parsed through.

The program will accept both IPv4 and IPv6 addresses and will name the output files accordingly. The IP addresses can be supplied either directly or through a file, an example file `ipFile.example` has been provided for you

See [automatedOSINT](./automatedOSINT.py) and [IPScan](./IPScan.py) for the code.

`.env` contains API keys for the OSINT API's and `.env.example` provides an example of the file
structure. A `.env` file will need to be present for the program to work so if you have no API keys just rename `.env.example ` to `.env`.

All logfiles from scans will be saved in the directory `IPLogFiles` in JSON format and named after their respective IP address. Ipv6 addresses will be named `ip6-xxxx-xxxx-...-xxxx.json` and IPv4 addresses will be named `ip4-xxx-xxx-xxx-xxx.json` and any IP that has previously been scanned will not be scanned twice so to rescan any IP address delete or rename the original logfile.



## Installation

### Installing Python

**Debian** : `sudo apt-get install python3.8`

**Arch** : `pacman -S python3.8`	



### Install Dependencies

```bash
$ python3 -m pip install -r requirements.txt
```



## Usage

### From the Terminal

**Scanning a specific IP Address**

```bash
$ python3 automatedOSINT.py -i <IP_Address>
```

**Scanning multiple IP Addresses**

```bash
$ python3 automatedOSINT.py -f <file containing ip addresses>
```

**Specifying an output directory**
```bash
$ python3 automatedOSINT.py -d <directory_to_write_file_in>
```

For the full list of options run the command:

```bash
$ python3 automatedOSINT.py -h
```



## API's

### Possible API's

- Shodan
- urlscan
- ThreatCrowd

The API's are not required for the scan to take place however the juicy information comes from the APIs so they will be very valuable.

Information about these APIs can be found here:

**Shodan:** https://shodan.readthedocs.io/en/latest/tutorial.html#installation

**urlscan:** https://urlscan.io/about-api/

**ThreatCrowd:** https://www.threatcrowd.org/

### Rate Limiting

All requests to the API's have been limited to no more than one request every 10 seconds. This was done as to not annoy any providers of these APIs and not cause any unintended Denial of Service.

## Language Information

This program was written and tested on `Python 3.8` there is no promise it will work with other python versions.
