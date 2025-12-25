#!/usr/bin/env python3
# This file is part of an external network pentest set of tools 
# created and maintained by Laurent Gaffie.
# email: lgaffie@secorizon.com
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
import argparse
import json
import os
import re
import requests
import sqlite3
import sys
import time
from urllib.parse import urlparse

VERSION = "1.0"
INDEX_URL = "https://index.commoncrawl.org/collinfo.json"
RESULTS_DIR = "results"
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "CCrawlDNS/1.0 (passive reconnaissance tool)"
})

def color(txt, code = 1, modifier = 0):
    if os.name == 'nt':
        return txt
    return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def Banner():
    Banner = r"""
   ██████╗ ██████╗ ██████╗  █████╗ ██╗    ██╗██╗     ██████╗ ███╗   ██╗███████╗
  ██╔════╝██╔═══╗  ██╔══██╗██╔══██╗██║    ██║██║     ██╔══██╗████╗  ██║██╔════╝
  ██║     ██║      ██████╔╝███████║██║ █╗ ██║██║     ██║  ██║██╔██╗ ██║███████╗
  ██║     ██║      ██╔══██╗██╔══██║██║███╗██║██║     ██║  ██║██║╚██╗██║╚════██║
  ╚██████╗╚██████╔╝██║  ██║██║  ██║╚███╔███╔╝███████╗██████╔╝██║ ╚████║███████║
   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═══╝╚══════╝

                            Passive Recon from history
                      Author: Laurent Gaffie, lgaffie@secorizon.com
                                x.com/@secorizon
"""
    return Banner

# DB handling
def get_db_path(domain):
    domain_clean = re.sub(r'[^\w\-.]', '_', domain.lower())
    domain_dir = os.path.join(RESULTS_DIR, domain_clean)
    os.makedirs(domain_dir, exist_ok=True)
    return os.path.join(domain_dir, f"{domain_clean}.db")

def create_db(db_path):
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subdomain TEXT UNIQUE,
            tech_detected TEXT,
            example_url TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_subdomain(db_path, subdomain, tech="", example_url=""):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO subdomains (subdomain, tech_detected, example_url)
        VALUES (?, ?, ?)
    """, (subdomain.lower(), tech, example_url))
    conn.commit()
    conn.close()

def fetch_index_list(years_filter: set[int] | None, max_per_year: int = 3) -> list[dict]:
    try:
        resp = SESSION.get(INDEX_URL, timeout=30)
        resp.raise_for_status()
        all_indexes = resp.json()

        if years_filter is None:
            print(f"[+] Loaded all {len(all_indexes)} Common Crawl indexes")
            return all_indexes

        by_year = {}
        for idx in all_indexes:
            match = re.search(r'CC-MAIN-(\d{4})', idx['id'])
            if match:
                year = int(match.group(1))
                if year in years_filter:
                    by_year.setdefault(year, []).append(idx)

        filtered = []
        for year in sorted(by_year.keys(), reverse=True):
            year_indexes = sorted(by_year[year], key=lambda x: x['id'], reverse=True)
            selected = year_indexes[:max_per_year]
            filtered.extend(selected)
            print(f"[+] Year {year}: using {len(selected)}/{len(by_year[year])} indexes")

        print(f"[+] Total selected: {len(filtered)} indexes from years {sorted(years_filter)}")
        return filtered

    except Exception as e:
        print(f"[-] Failed to fetch index list: {e}")
        sys.exit(1)


def extract_subdomain_from_url(url: str, target_domain: str) -> str | None:
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        target = target_domain.lower()
        if hostname == target or hostname.endswith('.' + target):
            return hostname
    except Exception:
        pass
    return None


def detect_tech_and_example(urls: list[str]) -> tuple[str, str | None]:
    extensions = {
        # PHP family
        '.php': 'PHP',
        '.php3': 'PHP',
        '.php4': 'PHP',
        '.php5': 'PHP',
        '.phtml': 'PHP',
        '.phar': 'PHP',

        # Microsoft
        '.asp': 'Classic ASP',
        '.aspx': 'ASP.NET',
        '.ascx': 'ASP.NET',
        '.asmx': 'ASP.NET Web Service',
        '.ashx': 'ASP.NET Handler',
        '.axd': 'ASP.NET Handler',
        '.master': 'ASP.NET Master Page',

        # Java
        '.jsp': 'Java JSP',
        '.jspx': 'Java JSP',
        '.do': 'Java Struts',
        '.action': 'Java Struts',

        # ColdFusion
        '.cfm': 'ColdFusion',
        '.cfml': 'ColdFusion',
        '.cfc': 'ColdFusion Component',

        # Perl & CGI
        '.pl': 'Perl',
        '.pm': 'Perl Module',
        '.cgi': 'CGI Script',

        # Python
        '.py': 'Python',

        # Ruby
        '.rb': 'Ruby',
        '.erb': 'Ruby on Rails',

        # Node.js / JavaScript
        '.js': 'JavaScript',
        '.mjs': 'JavaScript Module',

        # Go
        '.go': 'Go',

        # Rust
        '.rs': 'Rust',

        # Other
        '.lua': 'Lua',
        '.scala': 'Scala',
        '.dart': 'Dart (Flutter)',
        '.swift': 'Swift',
    }

    path_indicators = {
        # CMS
        '/wp-admin/': 'WordPress',
        '/wp-content/': 'WordPress',
        '/wp-includes/': 'WordPress',
        '/wp-json/': 'WordPress REST API',
        '/xmlrpc.php': 'WordPress XML-RPC',
        '/wp-login.php': 'WordPress Login',

        '/administrator/': 'Joomla/Drupal Admin',
        '/joomla/': 'Joomla',
        '/sites/all/': 'Drupal',
        '/user/login': 'Drupal',
        '/magento/': 'Magento',
        '/downloader/': 'Magento',
        '/skin/adminhtml/': 'Magento Admin',

        '/typo3/': 'TYPO3',
        '/typo3conf/': 'TYPO3',
        '/typo3temp/': 'TYPO3',

        '/concrete/': 'Concrete CMS',
        '/index.php?id=': 'Generic CMS (often Joomla/WordPress)',

        # Frameworks
        '/laravel/': 'Laravel (exposed?)',
        '/artisan': 'Laravel',
        '/public/index.php': 'Laravel/Symfony',

        '/rails/': 'Ruby on Rails',
        '/config.ru': 'Ruby on Rails',

        '/symfony/': 'Symfony',
        '/app_dev.php': 'Symfony Dev',

        '/yii/': 'Yii Framework',

        # Admin Panels
        '/admin/': 'Admin Panel',
        '/admin.php': 'Admin Panel',
        '/admin.html': 'Admin Panel',
        '/login/': 'Login Page',
        '/dashboard/': 'Dashboard',
        '/cpanel/': 'cPanel',
        '/webmail/': 'Webmail',

        # Database/Admin Tools
        '/phpmyadmin/': 'phpMyAdmin',
        '/pma/': 'phpMyAdmin',
        '/mysql/': 'MySQL Admin',
        '/adminer.php': 'Adminer',
        '/dbadmin/': 'Database Admin',

        # API & Modern
        '/api/': 'API Endpoint',
        '/v1/': 'API v1',
        '/v2/': 'API v2',
        '/graphql': 'GraphQL',
        '/rest/': 'REST API',
        '/swagger/': 'Swagger/OpenAPI',
        '/redoc/': 'Redoc',

        # Dev/Exposure
        '/.env': '.env exposed!',
        '/.git/': '.git exposed!',
        '/.svn/': '.svn exposed!',
        '/.hg/': '.hg exposed!',
        '/config.php': 'Config exposed',
        '/backup/': 'Backup directory',
        '/test/': 'Test directory',
        '/dev/': 'Development',
        '/debug/': 'Debug mode',
        '/node_modules/': 'Node.js (exposed)',
        '/package.json': 'Node.js/npm',

        # Common Tools
        '/jenkins/': 'Jenkins',
        '/hudson/': 'Jenkins/Hudson',
        '/sonar/': 'SonarQube',
        '/nexus/': 'Nexus Repository',
        '/artifactory/': 'Artifactory',
        '/gitlab/': 'GitLab',
        '/gogs/': 'Gogs',
        '/gitea/': 'Gitea',

        # Monitoring
        '/kibana/': 'Kibana',
        '/grafana/': 'Grafana',
        '/prometheus/': 'Prometheus',
        '/zabbix/': 'Zabbix',

        # E-commerce
        '/shop/': 'Shop System',
        '/cart/': 'E-commerce Cart',
        '/checkout/': 'E-commerce Checkout',
        '/opencart/': 'OpenCart',
        '/prestashop/': 'PrestaShop',
        '/oscommerce/': 'osCommerce',

        # Forums
        '/phpbb/': 'phpBB',
        '/forum/': 'Forum Software',
        '/discourse/': 'Discourse',
        '/vanilla/': 'Vanilla Forums',
    }


    tech_found = set()
    trigger_url = None

    for url in urls:
        path = urlparse(url).path.lower()

        for ext, tech in extensions.items():
            if path.endswith(ext):
                tech_found.add(tech)
                if not trigger_url:
                    trigger_url = url

        for pattern, tech in path_indicators.items():
            if pattern in path:
                tech_found.add(tech)
                if not trigger_url:
                    trigger_url = url

        if trigger_url:
            break

    if not tech_found:
        return "", urls[0] if urls else None

    tech_str = ", ".join(sorted(tech_found))
    return tech_str, trigger_url or urls[0]


def process_index(index_info: dict, target_domain: str, db_path: str):
    cdx_api = index_info['cdx-api']
    index_id = index_info['id']

    params = {
        'url': target_domain,
        'matchType': 'domain',
        'fl': 'url',
        'output': 'json',
        'pageSize': 2000
    }

    subdomain_data = {}

    max_retries = 3
    for attempt in range(max_retries):
        try:
            print(f"[+] Querying {index_id} (attempt {attempt + 1}/{max_retries})...")
            resp = SESSION.get(cdx_api, params=params, timeout=40)
            time.sleep(1)

            if resp.status_code == 503:
                wait = 5 * (2 ** attempt)
                print(f"    [~] 503 Throttled — waiting {wait}s...")
                time.sleep(wait)
                continue

            if resp.status_code != 200:
                print(f"    [-] {index_id}: HTTP {resp.status_code}")
                return

            lines = resp.text.strip().split('\n')
            if not lines or len(lines) <= 1:
                return

            count = 0
            for line in lines:
                try:
                    data = json.loads(line)
                    url = data.get('url')
                    if not url:
                        continue

                    subdomain = extract_subdomain_from_url(url, target_domain)
                    if not subdomain:
                        continue

                    subdomain_data.setdefault(subdomain, []).append(url)
                    count += 1
                except:
                    continue

            print(f"    [+] Extracted {count} records from {index_id}")
            break

        except Exception as e:
            print(f"    [-] Error querying {index_id}: {e}")
            if attempt < max_retries - 1:
                time.sleep(5)

    # Print all subdomains in original format
    for sub in sorted(subdomain_data.keys()):
        urls = subdomain_data[sub]
        tech, example = detect_tech_and_example(urls)
        tech_str = f" --> [{tech}]" if tech else ""
        print(f"    {sub}{tech_str}")
        if example and tech:
            print(f"       [URL]: {example}")

        # Always save subdomains (tech and example if available)
        save_subdomain(db_path, sub, tech if tech else "", example if tech else "")


def main():
    print(color(Banner(),2,1))
    parser = argparse.ArgumentParser(
        description="CCrawlDNS - Passive subdomain discovery using Common Crawl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 CCrawlDNS.py -d yahoo.com --years last2 --max-per-year 1
  python3 CCrawlDNS.py -d yahoo.com --years 2025 --max-per-year 3
        """
    )
    parser.add_argument('-d', '--domain', required=True, help="Target domain (e.g. x.com)")
    parser.add_argument('--years', type=str, default="last2", 
                        help="Years to query: comma-separated, 'all', or 'last2' (default)")
    parser.add_argument('--max-per-year', type=int, default=3,
                        help="Max number of indexes to use per year (default: 3)")
    args = parser.parse_args()

    target_domain = args.domain.lower().strip().rstrip('.')

    if args.years == "all":
        years_filter = None
    elif args.years == "last2":
        current = time.localtime().tm_year
        years_filter = {current, current - 1}
    else:
        try:
            years_filter = {int(y.strip()) for y in args.years.split(',') if y.strip().isdigit()}
        except:
            print("[-] Invalid --years format. Using 'last2'.")
            current = time.localtime().tm_year
            years_filter = {current, current - 1}

    print(f"[+] Starting CCrawldns against: {target_domain}")
    print(f"[+] Years: {years_filter if years_filter else 'all'} | max per year: {args.max_per_year}")

    # Create per-domain DB
    db_path = get_db_path(target_domain)
    create_db(db_path)

    indexes = fetch_index_list(years_filter, args.max_per_year)

    for idx in indexes:
        process_index(idx, target_domain, db_path)

    print("\n[+] Enumeration complete!")
    print(f"[+] Results saved in: {db_path}")

if __name__ == '__main__':
    main()
