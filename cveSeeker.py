import socket
import requests
import os
import json
import argparse
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

print(Fore.CYAN + """
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░     ░▒▓███████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░           ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░       ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░           ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░       ░▒▓█▓▒▒▓█▓▒░░▒▓██████▓▒░       ░▒▓██████▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░  
░▒▓█▓▒░        ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░                  ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░                  ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░   ░▒▓██▓▒░  ░▒▓████████▓▒░     ░▒▓███████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                                                                          
                            Unveiling Cyber Threats: From assets to Vulnerability Insights   
                                     Coded with Love by Anmol K Sachan @FR13ND0x7F                                                                                                                
""" + Style.RESET_ALL)

# Define the argument parser
parser = argparse.ArgumentParser(description="Fetch domain IPs, open ports, CVEs, and POCs")
parser.add_argument('--file', required=True, help="Input file containing domains and IPs")
parser.add_argument('--project', required=True, help="Project name for storing results")
args = parser.parse_args()

input_file = args.file
project_name = args.project
db_folder = "LastScans"

# Ensure the db folder exists
os.makedirs(db_folder, exist_ok=True)

# Initialize counters and storage
domains = set()
ips = set()
alive_domains = set()
not_reachable_domains = set()
domain_ip_mapping = {}
unique_ips = set()

# Read input file
with open(input_file, 'r') as file:
    lines = file.readlines()
    for line in lines:
        item = line.strip()
        if item:
            if item.replace('.', '').isdigit():  # Basic check for IP
                ips.add(item)
            else:
                domains.add(item)

print(Fore.YELLOW + f"-------------Stats-------------")
print(Fore.GREEN + f"[+] Domains Found: {len(domains)}")
print(Fore.GREEN + f"[+] IP Found: {len(ips)}")

# Resolve domains to IPs
for domain in domains:
    try:
        ip_address = socket.gethostbyname(domain)
        alive_domains.add(domain)
        domain_ip_mapping[domain] = ip_address
        unique_ips.add(ip_address)
    except socket.gaierror:
        not_reachable_domains.add(domain)

# Store domain:IP mapping in a project-specific file
project_file = os.path.join(db_folder, f"{project_name}.json")
with open(project_file, 'w') as pf:
    json.dump(domain_ip_mapping, pf, indent=4)

print(Fore.GREEN + f"[+] Alive domains: {len(alive_domains)}")
print(Fore.RED + f"[+] Not reachable: {len(not_reachable_domains)}")

# Combine user-provided IPs and resolved IPs, removing duplicates
all_ips = ips.union(unique_ips)
total_ips = len(all_ips)
duplicates = len(ips) + len(unique_ips) - total_ips
unique_ip_count = len(all_ips)

print(Fore.GREEN + f"[+] Total IP: {total_ips}")
print(Fore.YELLOW + f"[+] Duplicates: {duplicates}")
print(Fore.GREEN + f"[+] Unique: {unique_ip_count}")
print(Fore.YELLOW + f"-------------------------------")

# Fetch CVEs for each IP
print(Fore.YELLOW + "\n[+] Looking for CVEs")
cve_data = {}

not_found_cves = []  # To collect CVEs not found

def fetch_pocs_and_print(ip, hostnames, cve_info):
    """Fetch POCs for CVEs and print the results."""
    print(Fore.YELLOW + f" [+] Fetching POCs for CVEs (Total Number of CVEs identified: {len(cve_info)})")
    found_pocs = 0
    for cve in cve_info:
        poc_response = requests.get(f"https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve}")
        if poc_response.status_code == 200:
            pocs = poc_response.json().get('pocs', [])
            if pocs:
                found_pocs += 1
                print(Fore.GREEN + f"  [+] POC for {cve} Found:")
                for poc in pocs:
                    print(Fore.CYAN + f"    {poc['html_url']}")
            else:
                not_found_cves.append(cve)
        else:
            print(Fore.RED + f"[-] Failed to fetch POCs for {cve}")
    print(Fore.YELLOW + f"  [+] STATS: POCs found for {found_pocs} out of {len(cve_info)} identified CVEs")

for ip in all_ips:
    response = requests.get(f"https://internetdb.shodan.io/{ip}")
    if response.status_code == 200:
        data = response.json()
        open_ports = data.get('ports', [])
        cve_info = data.get('vulns', [])
        hostnames = data.get('hostnames', [])
        if hostnames:
            hostname_str = f"({'/'.join(hostnames)})"
        else:
            hostname_str = ''
        if open_ports:
            print(Fore.GREEN + f"[+] {ip}{hostname_str} (Open Ports): {', '.join(map(str, open_ports))}")
        if cve_info:
            print(Fore.RED + f"[+] {ip}{hostname_str} : {', '.join(cve_info)}")
            fetch_pocs_and_print(ip, hostnames, cve_info)
        else:
            print(Fore.GREEN + f"[+] {ip}{hostname_str} : No CVEs Found")
    else:
        print(f"[+] {ip} : Failed to fetch CVEs")

# Print CVEs not found at the end
if not_found_cves:
    print(Fore.RED + f"[-] CVEs not found for {', '.join(not_found_cves)}")
