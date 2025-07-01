# Spider_Task2

# Required Libraries
- argparse
- json
- requests
- sublist3r
- dns.resolver
- whois
- subprocess
- geoip2.database

Installing the Libraries:
``` sh
pip install <module_name>
```

# Level 1

# Usage:
```sh
  ./Basic_Recon.py [FLAGS]
```
```yaml
Flags:
INPUT:
  -d  domain
  -nd out of scope domains
  -I ip_address
OUTPUT:
  -o output file
HELP:
  -h help
```

# Level 2

# Usage:
```sh
./intermediate_recon.py [FLAGS]
```

```yaml
Flags:
INPUT:
  -d     domain
  -nd    out_of_scope_domains
  -I     IP_Address
  -c     Fetch subdomains from crtsh
  -s     Fetch subdomains using sublist3r
  -dns   Fetch dns info
  -w     Use whois to fetch domain info
  -hthe  Fetch http headers
  -sf    Fetch Static Files
  -g     Fetch geo_ip info
  -wweb  Use whatweb for technology detection
  -sh    Use shodan to discover open ports and services
  -e     Use theHarvester to fetch emails
OUTPUT:
  -o     Output File
HELP:
-h       Help (Display this image)
```
