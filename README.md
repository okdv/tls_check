# TLS Check

Bulk validate TLS Certicates from a CSV and warn against upcoming expiration

## Installation

Must have [Python](https://www.python.org/downloads/) installed

Option A) Clone repo from [git.otho.dev](https://git.otho.dev/okdv/tls_check) or [github](https://github.com/okdv/tls_check)

```bash
# git.otho.dev
git clone https://git.otho.dev/okdv/tls_check.git
# github
git clone https://github.com/okdv/tls_check.git
```
Option B)  Download repo from [git.otho.dev](https://git.otho.dev/okdv/tls_check) or [github](https://github.com/okdv/tls_check), and unzip
![download from git.otho.dev](https://github.com/okdv/tls_check/assets/forgejo_download.png)
![download from github](https://github.com/okdv/tls_check/assets/github_download.png)

## Usage

Open downloaded tls_check directory in terminal (bash, powershell)

### Examples
```bash
# get help
py main.py --help

# basic usage
py main.py [-h] [-s SOURCE] [-d DEST] [-c COLUMN] [-t TIMEOUT] [-u URL_QUERY] [-p] [-v | -q | -T THRESHOLD]

# options
# option name, short cmd, cmd            description            default value
help, -h, --help            "show this help message and exit"
SOURCE, -s, --source            "file path to csv of domains"            'data.csv'
DEST, -d, --dest            "file path to csv result of TLS validations"            'results.csv'
COLUMN, -c, --column            "header or index for column containing URLs to validate"            0
TIMEOUT, -t, --timeout            "skip domains if response exceeds X seconds"            30
URL_QUERY, -u, --url-query            "query URL for third party TLS validation service, use [DOMAIN] to inject domain into URL"            'https://www.ssllabs.com/ssltest/analyze.html?d=[DOMAIN]'
PRESERVE, -p, --preserve            "preserve columns from --source, append after generated colomns in --dest"

# only include 0 or 1 of the below options
VERBOSE, -v, --verbose            "log everything"
QUIET, -q, --quiet            "log nothing"
THRESHOLD, -T, --threshold            "log if expires within X days or less"
```

```bash
py main.py [-h] [-s SOURCE] [-d DEST] [-c COLUMN] [-t TIMEOUT] [-u URL_QUERY] [-p] [-v | -q | -T THRESHOLD]
```

### Example usage

```bash
py main.py --column url --source dummy-data.csv --dest dummy-results.csv --timeout 30 --preserve --verbose

# short form (with some syntax changes, is still same as above)
py main.py -c 'url' -s './dummy-data.csv' -d './dummy-results.csv' -t 30 -p -v
```

Attached dummy-*.csv files are a real input/result from running the script using options above

### Environment
This script supports use of environment variables as well as options listed above. To use, set environment variables (that can be read by the script) using the following syntax `TLS_CHECK_[OPTION_NAME]`, e.g. `TLS_CHECK_SOURCE`, `TLS_CHECK_DEST`, etc. 

Note: simple `store_true` options like `--verbose` or `--preserve` must still be explicitly included, they are not available as environment variables

If an environment variable is present then it will be used as a **default value** for its respective option, if that option is explicitly provided while running the script then **it will override the environment**. If neither are provided then standard defaults above are used.


## Contributing

Pull requests are welcome. Feel free to open an issue for a request, however note that this is a purpose driven script so changes may be denied, in which case fork away. 

## License

[MIT](https://choosealicense.com/licenses/mit/)