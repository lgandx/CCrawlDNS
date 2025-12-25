# CCrawlDNS #

CommonCrawl data set subdomain extracter.

Author: Laurent Gaffie <lgaffie@secorizon.com >  https://secorizon.com > https://x.com/@secorizon



## Intro ##

CCrawlDNS is a small pentest utility that make use of the CommonCrawl data set API (petabytes of data!). 

This tool is highly customizable and is specifically designed for pentesters. Once configured for a scan, it will make multiple queries to CommonCrawl.org and will fetches all collected subdomains related to the DNS you provided as target. You can specify which years are of interest (from 2008 onward), from how many dataset per year, all results will be stored in a DB.

New options added: scans are now highly customizable, you can search by specific year and datasets. 
- ✅ Search by specific year and datasets. 
- ✅ Automatic path fingerprint.
- ✅ Automatic web language fingerprint.
- ✅ Automatic throttling.
- ✅ All results are saved in a db.

## Usage ##

Running the tool:

    //Search all collected subdomains for yahoo.com in the past 2 years, include 1 dataset per year (most efficient)
    python3 ccrawldns.py -d yahoo.com --years last2 --max-per-year 1

    //Search all collected subdomains for yahoo.com only in 2025, include 3 dataset
    python3 CCrawlDNS.py -d yahoo.com --years 2025 --max-per-year 3

    //Search all collected subdomains for yahoo.com for the year 2025 and 2021, include 1 dataset
    python3 CCrawlDNS.py -d yahoo.com --years 2025, 2021 --max-per-year 1
    
    //Search all collected subdomains for yahoo.com from 2008 to now, include 1 dataset (much slower, but complete)
    python3 CCrawlDNS.py -d yahoo.com --years all --max-per-year 1

