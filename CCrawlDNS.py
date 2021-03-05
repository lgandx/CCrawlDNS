#!/usr/bin/env python3
# This file is part of an external network pentest set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import requests, json, optparse, re, os, sys, multiprocessing, sqlite3

parser = optparse.OptionParser(usage='python %prog -p -f asp -d microsoft.com', prog=sys.argv[0])
parser.add_option('-d','--domain', action="store", help="Target domain", dest="Domain", default=None)
parser.add_option('-p','--printurl', action="store_true", help="Print all collected URL", dest="PrintURL", default=None)
parser.add_option('-f','--FileExt', action="store", help="Print collected URL with the following file extension", dest="FileExt", default=None)
options, args = parser.parse_args()
Target = options.Domain
PrintURL = options.PrintURL
FileExt = options.FileExt

if Target is None:
	sys.exit('Mandatory option -d missing.\nExiting...')

def DbConnect():
    cursor = sqlite3.connect('./Results.db')
    return cursor

def CreatePentestDb():
	if os.path.exists('./Results.db'):
		cursor = DbConnect()
		cursor.execute('DROP TABLE SubDomain')
		cursor.commit()
		cursor.execute('CREATE TABLE SubDomain (timestamp TEXT, Domain TEXT, Links Text)')
		cursor.commit()
		cursor.close()
	if not os.path.exists('./Results.db'):
		cursor = DbConnect()
		cursor.execute('CREATE TABLE SubDomain (timestamp TEXT, Domain TEXT, Links Text)')
		cursor.commit()
		cursor.close()

def SaveSubDomainToDb(result):
	for k in [ 'timestamp', 'Domain', 'Links']:
		if not k in result:
			result[k] = ''
	cursor = DbConnect()
	cursor.text_factory = sqlite3.Binary
	res = cursor.execute("SELECT COUNT(*) AS count FROM SubDomain WHERE Domain=? AND Links=?", (result['Domain'], result['Links']))
	(count,) = res.fetchone()
	if not count:
		cursor.execute("INSERT INTO SubDomain VALUES(datetime('now'), ?, ?)", (result['Domain'], result['Links']))
		cursor.commit()
	cursor.close()

def GetSubdomainStatistic(cursor):
     res = cursor.execute("SELECT COUNT(DISTINCT UPPER(Domain)) FROM SubDomain")
     for row in res.fetchall():
         print('\n[+] In total {0} unique subdomains were retrieved.'.format(row[0]))

def GetSubdomains(cursor):
     res = cursor.execute("SELECT DISTINCT Domain FROM SubDomain")
     for row in res.fetchall():
         print('Subdomain found: {0}'.format(row[0]))

def GetLinks(CdxApi, IndexNum):
	print("Processing {0}".format(IndexNum))
	Req = requests.get(CdxApi+'?url='+Target+'&fl=url&matchType=domain&pageSize=2000&output=json')
	Ans = Req.text.split('\n')[:-1]
	try:
		for entry in Ans:
			Url = json.loads(entry)['url']
			if PrintURL is True and FileExt is not None:
				URLZ = re.findall(FileExt, Url)
				if URLZ:
					print(Url)
			if PrintURL is True and FileExt is None:
				print(Url)

			Domains =  re.findall(r'(?<=://)[^/|?|#]*', Url)[0]
			SaveSubDomainToDb({
					'Domain': Domains
					})
		print("{0} Processed".format(IndexNum))
	except:
		pass

def GetIndexFile():
	IndexURL = "https://index.commoncrawl.org/collinfo.json"
	Data = requests.get(IndexURL).text
	Indexes = json.loads(Data)
	threads = []
	print("You have %s CPUs...\nLet's use them all!"%multiprocessing.cpu_count())
	Pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
	for res in Indexes:
		proc = Pool.apply_async(GetLinks, (res['cdx-api'],(res['id'])))
		threads.append(proc)
	for proc in threads:
		proc.get()

def main():
	CreatePentestDb()
	cursor = DbConnect()
	GetIndexFile()
	GetSubdomainStatistic(cursor)
	GetSubdomains(cursor)

if __name__ == '__main__':
	main()
