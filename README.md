# CCrawlDNS #

CommonCrawl data set subdomain extracter.

Author: Laurent Gaffie <laurent.gaffie@gmail.com >  https://g-laurent.blogspot.com



## Intro ##

CCrawlDNS is a small pentest utility that make use of the CommonCrawl data set API (petabytes of data!). This tool will make multiple queries to CommonCrawl.org and fetches all collected subdomains since 2008 related to the DNS you provided as target and will store in a DB all unique subdomains.

This tool uses multiprocessing for performance enhancement.

New option added: Ability to print all collected URLs for a given domain and search by file extensions.

## Usage ##

Running the tool:

    python CCrawlDNS.py -d example.com

    python3 CCrawlDNS.py -d example.com

    Print all URLs:

    python CCrawlDNS.py -d example.com -p

    Print all URLs with the file extension ".asp":

    python CCrawlDNS.py -d example.com -p -f .asp

## Requirements ##

    pip install requests
