#!/usr/bin/python3

import subprocess
import argparse
import time
import json

def get_screenshots_from_gowitness(subdomains):
    subprocess.run(["mkdir","-p","reports/screenshots"])
    timestamp = time.time()
    protocol ="http"
    for sub in subdomains:
        sub=sub.strip()
        filename = f"reports/screenshots/"
        url =f"{protocol}://{sub}"
        try:
            subprocess.run(["gowitness","scan","single","-u",url, "-s", filename,"--write-jsonl"])
            print(f"Screenshot saved for {sub} at {filename}")
        except Exception as e:
            print(f"Error getting screenshot for {sub}: {e}")

def get_waf_details(all_subdomains,output_file):
    waf_results = {}
    for sub in all_subdomains:
        try:
            result= subprocess.run(["wafw00f","-a",sub,"-f","json"],capture_output=True)
            if result.returncode == 0:
                waf_json =json.loads(result.stdout)
                waf_results[sub] = waf_json
            print(f"WAF details saved for {sub}")
        except Exception as e:
            print(f"Error getting WAF details for {sub}: {e}") 
    if waf_results:
        with open(output_file, "a") as f:
            json.dump(waf_results,f,indent=4)

def get_vulnerability_details(all_subdomains, output_file):
    print("Starting vulnerabilty scan .... ")
    vuln_details= {}
    for sub in all_subdomains:
        try:
            result= subprocess.run(["nikto","-host",sub,"-F","json","-output","-"],capture_output=True)
            if result.returncode == 0:
                vuln_json = json.loads(result.stdout)
                vuln_details[sub] = vuln_json
                print(f"Vulnerability details saved for {sub}")
        except Exception as e:
            print(f"Error getting vulnerabilty details for {sub}: {e}")
    if vuln_details:
        with open(output_file, "a") as f:
            json.dump(vuln_details, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description="Live Recon Script")
    parser.add_argument("-s","--screenshots",action="store_true", help ="Get screenshots of subdomains from Gowitness")
    parser.add_argument("-w","--waf",action="store_true",help="Get WAF details of subdomains using wafw00f tool")
    parser.add_argument("-v","--vuln_scanner", action="store_true",help="Get vulnerability details of subdomains using Nikto")
    parser.add_argument("-o","--output",help= "Output file to save results(default: output.json)")

    args = parser.parse_args()

    output_file = args.output

    with open("example.json", "r") as f:
        Recon_data =json.load(f)

    all_subdomains = []
    if "crtsh_domains" in Recon_data:
        all_subdomains.extend(Recon_data.get("crtsh_domains",[]))
    if "sublist3r_domains" in Recon_data:
        all_subdomains.extend(Recon_data.get("sublist3r_domains",[]))

    all_subdomains = list(set(all_subdomains))

    if args.screenshots:
        get_screenshots_from_gowitness(all_subdomains)
    if args.waf:
        get_waf_details(all_subdomains, output_file)
    if args.vuln_scanner:
        get_vulnerability_details(all_subdomains, output_file)

if __name__ == "__main__":
    main()
  
