from urllib.request import Request, urlopen, ssl, socket
from urllib.error import URLError, HTTPError
from datetime import datetime, date
from collections import OrderedDict
import json, argparse, csv, re, os

parser = argparse.ArgumentParser(description="bulk validate TLS certificates")
parser.add_argument('-s', '--source', type=str, action="store", help="file path to csv of domains", default="data.csv")
parser.add_argument('-d', '--dest', type=str, action="store", help="file path to csv result of TLS validations", default="results.csv")
parser.add_argument('-c', '--column', action="store", help="header or index for column containing URLs to validate", default=0)
parser.add_argument('-t', '--timeout', action="store", type=int, help="skip domains if response exceeds X seconds", default=30)
parser.add_argument('-u', '--url-query', action="store", type=str, help="query URL for third party TLS validation service, use [DOMAIN] to inject domain into URL", default="https://www.ssllabs.com/ssltest/analyze.html?d=[DOMAIN]")

group = parser.add_mutually_exclusive_group()
group.add_argument('-v', '--verbose', action="store_true", help="log everything")
group.add_argument('-q', '--quiet', action="store_true", help="log nothing")
group.add_argument('-T', '--threshold', action="store", type=int, help="log if expires within X days or less", default=7)

args = parser.parse_args()
context = ssl.create_default_context()

def printer(data, critical=False, threshold = 0):
    if args.verbose:
        print(data)
    elif args.quiet:
         pass
    elif args.threshold >= threshold:
        if critical:
            print(data)
        else:
            pass

def validate(hostname):
    with socket.create_connection((hostname, '443'), timeout=args.timeout) as sock:
        try:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                data = ssock.getpeercert()
                valid_from = datetime.strptime(data['notBefore'], '%b %d %H:%M:%S %Y %Z').date()
                valid_to = datetime.strptime(data['notAfter'], '%b %d %H:%M:%S %Y %Z').date()
                today = date.today()
                x_days_ago = (today - valid_from).days
                x_days_to = (valid_to - today).days
                url_query = re.sub('\[DOMAIN\]', hostname, args.url_query)
                return {
                    "domain": hostname,
                    "valid": True if (x_days_ago >= 0 and x_days_to > 0) else False,
                    "since": str(x_days_ago),
                    "to": str(x_days_to),
                    "url-query": url_query
                }
        except:
            return {
                "domain": hostname,
                "valid": False,
                "since":"",
                "to":"",
                "url-query": url_query
            }

with open(args.source, "r", newline='') as infile, open(args.dest, "w", encoding="utf8", newline='') as outfile:
    domains = set()
    writer = csv.writer(outfile)
    try:
        col = int(args.column)
        reader = csv.reader(infile)
        printer("Treating --column as an index")
    except: 
        col = str(args.column)
        reader = csv.DictReader(infile)
        printer("Treating --column as a header (string)")

    writer.writerow(['domain', 'passed TLS check', 'days since certificate start', 'days until certificate expire', 'external query url'])
    for row in reader:
        if row[col] and len(row[col]) > 0:
            hostname_search = re.search('^(?!http\:\/\/)(?:https\:\/\/)?([a-zA-Z0-9-.]*).*$', row[col], re.IGNORECASE)
            if hostname_search and hostname_search.group(1):
                domains.add(hostname_search.group(1))
            else:
                printer(row[col] + ": Skipped, please make sure this is a valid URL and it supports HTTPS", False)
        else:
            printer('Skipped empty row')

    for domain in domains:
        printer("Validating " + domain + "...")
        try:
            obj = validate(domain)
            printer(obj, True, int(obj["to"]))
            writer.writerow([obj["domain"], str(obj["valid"]), obj["since"], obj["to"], obj["url-query"]])        
        except:
            printer(domain + ": Unable to validate, likely due to a timeout, unexpected response or invalid domain", True)
            writer.writerow([domain, "False", "", "", "Possibly timed out, invalid response, or already expired certificate"])
            pass