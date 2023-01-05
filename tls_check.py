from urllib.request import Request, urlopen, ssl, socket
from urllib.error import URLError, HTTPError
from datetime import datetime, date
import json, argparse, csv, re

parser = argparse.ArgumentParser(description="bulk validate TLS certificates")
parser.add_argument('-f', '--from', type=str, action="store", help="file path to csv of domains", default="./test-data.csv")
parser.add_argument('-t', '--to', type=str, action="store", help="file path to csv result of TLS validations", default="./results.csv")
parser.add_argument('-c', '--column', action="store", help="header or index for column containing URLs to validate", default=0)

args = parser.parse_args()
varArgs = vars(args)
from_file = varArgs['from']
to_file = varArgs['to']
col = varArgs['column']
context = ssl.create_default_context()
res_list = []

def validate(hostname):
    with socket.create_connection((hostname, '443')) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            data = ssock.getpeercert()
            valid_from = datetime.strptime(data['notBefore'], '%b %d %H:%M:%S %Y %Z').date()
            valid_to = datetime.strptime(data['notAfter'], '%b %d %H:%M:%S %Y %Z').date()
            today = date.today()
            x_days_ago = (today - valid_from).days
            x_days_to = (valid_to - today).days
            return {
                "domain": hostname,
                "valid": True if (x_days_ago > 0 and x_days_to > 0) else False,
                "since": str(x_days_ago),
                "to": str(x_days_to)
            }

with open(from_file, newline='') as file:
    try:
        col = int(col)
        reader = csv.reader(file)
    except ValueError:
        col = str(col)
        reader = csv.DictReader(file)

    for row in reader:
        hostname_search = re.search('^(?:http\:\/\/)?([a-zA-Z0-9-.:]*).*$', row[col], re.IGNORECASE)
        if hostname_search:
            hostname = hostname_search.group(1)
            try:
                validation_obj = validate(hostname)
                print(validation_obj);
                res_list.append(validation_obj)
            except:
                pass

with open(to_file, 'w', newline='') as res_file:
    print(type(res_list))
    wr = csv.writer(res_file, quoting=csv.QUOTE_ALL)
    wr.writerow(['domain', 'passed TLS check', 'days since certificate start', 'days until certificate expire'])
    for res in res_list:
        wr.writerow([res['domain'], str(res['valid']), res['since'], res['to']])