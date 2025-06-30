#!/usr/bin/python3

import argparse
import requests
import json
import sublist3r
import dns.resolver
import dnsrecon
import whois
import subprocess
import geoip2.database


def get_crtsh_domains(domain, out_of_scope):
    print(f"Fetching domains from crt.sh")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url)
        r.raise_for_status()
        data = r.json()
        subdomains = []

        for i in data:
            for name in i.get("name_value").split('\n'):
                name = name.strip()
                if domain in name and not any(a in name for a in out_of_scope):
                    subdomains.append(name)
        return list(set(subdomains))
    except Exception as e:
        print(f"Error getting crt.sh data: {e}")
        return []

def get_sublist3r_domains(domain, out_of_scope,output_file):
    print(f"Getting subdomains from sublist3r")
    try:
        subdomains = sublist3r.main(domain, 40, ports=None, silent=True, verbose=False, enable_bruteforce=False,
                                    engines=None, savefile=output_file)
        filtered_subdomains = [sub for sub in subdomains if
                               domain in sub and not any(a in sub for a in out_of_scope)]  # List comprehension
        return list(set(filtered_subdomains))
    except Exception as e:
        print(f"Error getting sublist3r subdomains: {e}")
        return []


def get_dns_records(domain):
    print(f"Fetching DNS Records for {domain}")
    dns_records = {}
    dns_types = ['A', 'NS', 'MX']
    for d_types in dns_types:
        try:
            answers = dns.resolver.resolve(domain, d_types, raise_on_no_answer=False)
            dns_records[dns_types] = [answers.to_text() for dns_data in answers]

        except Exception as e:
            print(f"Error fetching DNS records for {domain} for type {d_types}")
            dns_records = []

    return dns_records


def get_whois_domains(domain):
    print(f"Fetching whois data for {domain}")
    try:
        data = whois.whois(domain)
        return {key: value for (key, value) in data.items() if
                value}  # Using Dictionary comprehension to the dictionary of whois data
    except Exception as e:
        print(f"Error fetching whois data :{e}")
        print("Trying CLI whois fallback")
        try:
            result = subprocess.run(['whois', domain], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout
            else:
                print(f"CLI whois returned no ouptput ")
                return {}
        except Exception as ex:
            print(f"Error running CLI whois command: {ex}")
            return {}


def get_http_ServerBanners(domain):
    print(f"Fetching HTTP Server Banners for {domain}")
    try:
        url = f"http://{domain}"
        response = requests.get(url)
        if response.status_code == 200:
            server_banners = response.headers.get('Server')
            return {"Servers": server_banners} if server_banners else {"Servers": "No server banner found"}
    except Exception as e:
        print(f"Error getting HTTP Server Banners: {e}")
        return {"Servers": "Error"}


def get_Static_Files(domain):
    print(f"Fetching Static files for {domain}")
    files = {}
    for p in ['robots.txt','site.xml']:
        try:
            url = f'http://{domain}/p'
            response = requests.get(url)
            if response.status_code == 200:
                files[p] = response.text.split()
            else:
                files[p] = f"Error fetching {p}:{response.status_code} "
        except Exception as e:
            print(f"Error fetching static files:{e}")
    return files


def get_geoip_info(domain):
    print("Fetching GeoIP information")
    try:
        ip = requests.get(f"https://dns.google/resolve?name={domain}").json()['Answer'][0]['data']
        reader = geoip2.database.Reader(r'D:\GeoLite2\GeoLite2-City.mmdb')
        response = reader.city(ip)
        geoip_info = {
            "country": response.country.name,
            "city": response.city.name,
            "Latitude": response.location.latitude,
            "Longitude": response.location.longitude
        }
        return geoip_info
    except Exception as e:
        print(f"Error fetching GeoIP information: {e}")
        return {}


def main():
    print("Before running this script, ensure you have the required libraries installed: requests, argparse, and json.")

    parser = argparse.ArgumentParser(description="Recon Automation Script")
    parser.add_argument("-d", "--domain", required=True, help="Domain Name ")
    parser.add_argument("-I", "--ip_address", help="IP_Address")
    parser.add_argument("-nd", "--out_of_scope", default="", help="Out of scope domains")
    parser.add_argument("-o", "--output", help="Output file name")

    args = parser.parse_args()

    domain = args.domain
    ip_address = args.ip_address
    out_of_scope = args.out_of_scope.split(',') if args.out_of_scope else []
    output_file = args.output

    Recon_data = {
        "domain": domain,
        "crtsh_domains": get_crtsh_domains(domain, out_of_scope),
        "sublist3r_domains": get_sublist3r_domains(domain, out_of_scope, output_file),
        "dns_domains": get_dns_records(domain),
        "whois_domains": get_whois_domains(domain),
        "http_headers": get_http_ServerBanners(domain),
        "Static_Files": get_Static_Files(domain),
        "geoip_info": get_geoip_info(domain)
    }

    if output_file:
        try:
            with open(output_file, 'w') as f:
                json.dump(Recon_data, f, indent=4)
                print(f"Output Saved to {output_file}")
        except Exception as e:
            print(f"Error saving to file: {e} ")

    print(Recon_data)


if __name__ == "__main__":
    main()
