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
                                     Coded with Love by Anmol K Sachan @FR13ND0x7F                       Version 2.0                                                                                                     
""" + Style.RESET_ALL)

# Define the argument parser
parser = argparse.ArgumentParser(description="Fetch domain IPs, open ports, CVEs, and POCs")
parser.add_argument('--file', help="Input file containing domains and IPs")
parser.add_argument('--project', help="Project name for storing results")
parser.add_argument('--cve', help="CVE ID for fetching POCs")
args = parser.parse_args()

# Create output folder structure
def create_output_directory(project_name):
    output_dir = os.path.join("LastScans", project_name)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

# Function to fetch and return POCs for a given CVE
def fetch_pocs_for_cve(cve_id):
    try:
        response = requests.get(f"https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve_id}")
        if response.status_code == 200:
            return response.json().get('pocs', [])
        else:
            print(Fore.RED + f"[-] Failed to fetch POCs for {cve_id}")
    except requests.RequestException as e:
        print(Fore.RED + f"[-] Error fetching POCs: {e}")
    return []

# Function to fetch POCs and print them, now including storing relevant assets
def fetch_pocs_and_print(ip, hostnames, cve_info):
    found_cve_count = 0
    total_cve_count = len(cve_info)
    for cve in cve_info:
        pocs = fetch_pocs_for_cve(cve)
        if pocs:
            found_cve_count += 1
            print(Fore.CYAN + f"[+] Found POC for {cve}")
            print(Fore.YELLOW + "  [+] Links:")
            for poc in pocs:
                print(Fore.YELLOW + f"    - {poc['html_url']}")
        if cve not in cve_data:
            cve_data[cve] = {'assets': [], 'pocs': []}
        cve_data[cve]['assets'].append(ip)
        cve_data[cve]['pocs'].extend([poc['html_url'] for poc in pocs])
    
    if found_cve_count > 0:
        print(Fore.YELLOW + f"[[+] Found] [{found_cve_count}/{total_cve_count}] for asset {ip}")


# Create JSON and HTML reports
def create_reports(output_dir, domain_ip_mapping, alive_domains, not_reachable_domains, cve_data, open_ports_mapping):
    # JSON output
    output_json = {
        "alive_assets": {domain: {"ip": ip, "open_ports": open_ports_mapping[domain]} for domain, ip in domain_ip_mapping.items() if domain in alive_domains},
        "dead_assets": {domain: None for domain in not_reachable_domains},
        "cve_data": {}
    }
    
    for cve, data in cve_data.items():
        output_json['cve_data'][cve] = {
            'assets': data['assets'],
            'pocs': data['pocs']
        }
    
    json_file_path = os.path.join(output_dir, "report.json")
    with open(json_file_path, 'w') as json_file:
        json.dump(output_json, json_file, indent=4)

    # HTML output
    html_content = f"""
    <html>
    <head>
        <title>Scan Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f4f4f4;
                color: #333;
            }}
            h2 {{
                color: #0056b3;
            }}
            input[type="text"] {{
                width: 300px;
                padding: 10px;
                margin-bottom: 20px;
                border: 1px solid #ccc;
                border-radius: 4px;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin-bottom: 20px;
                background-color: #fff;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }}
            th, td {{
                border: 1px solid #dddddd;
                text-align: left;
                padding: 12px;
            }}
            th {{
                background-color: #007bff;
                color: white;
            }}
            tr:nth-child(even) {{
                background-color: #f2f2f2;
            }}
            tr:hover {{
                background-color: #e9ecef;
            }}
        </style>
        <script>
            function search() {{
                var input = document.getElementById("search").value.toLowerCase();
                var rows = document.querySelectorAll("table tr");
                rows.forEach(row => {{
                    if (row.textContent.toLowerCase().includes(input)) {{
                        row.style.display = "";
                    }} else {{
                        row.style.display = "none";
                    }}
                }});
            }}
        </script>
    </head>
    <body>
        <h2>Scan Report</h2>
        <input type="text" id="search" onkeyup="search()" placeholder="Search Report...">
        <h3>Statistics</h3>
        <table>
            <tr><th>Statistic</th><th>Value</th></tr>
            <tr><td>Domains Found</td><td>{len(domain_ip_mapping)}</td></tr>
            <tr><td>IP Found</td><td>{total_ips}</td></tr>
            <tr><td>Alive Domains</td><td>{len(alive_domains)}</td></tr>
            <tr><td>Not Reachable</td><td>{len(not_reachable_domains)}</td></tr>
            <tr><td>Total IP</td><td>{total_ips}</td></tr>
            <tr><td>Duplicates</td><td>{duplicates}</td></tr>
            <tr><td>Unique IPs</td><td>{unique_ip_count}</td></tr>
        </table>
        <h3>CVE Data</h3>
        <table>
            <tr><th>CVE</th><th>Assets</th><th>POCs</th></tr>
            {''.join([
                f'<tr><td>{cve}</td><td>{", ".join(data["assets"])}</td><td>{", ".join(data["pocs"])}</td></tr>'
                for cve, data in output_json['cve_data'].items()
            ])}
        </table>
        <h3>Alive Assets</h3>
        <table>
            <tr><th>Domain</th><th>IP</th><th>Open Ports</th></tr>
            {''.join([f'<tr><td>{domain}</td><td>{ip_info["ip"]}</td><td>{", ".join(map(str, ip_info["open_ports"]))}</td></tr>' for domain, ip_info in output_json['alive_assets'].items()])}
        </table>
        <h3>Dead Assets</h3>
        <table>
            <tr><th>Domain</th><th>Status</th></tr>
            {''.join([f'<tr><td>{domain}</td><td>Not Reachable</td></tr>' for domain in output_json['dead_assets']])}
        </table>
        <h3>Scope Details</h3>
        <table>
            <tr><th>Scope</th></tr>
    """

    # Read the input file directly to include in the HTML
    if input_file:
        try:
            with open(input_file, 'r') as f:
                scope_lines = f.readlines()
                for scope in scope_lines:
                    html_content += f'<tr><td>{scope.strip()}</td></tr>'
        except FileNotFoundError:
            print(f"[-] The file {input_file} does not exist.")
            html_content += '<tr><td colspan="1">Scope file not found.</td></tr>'  # Provide feedback in the report

    html_content += """
        </table>
    </body>
    </html>
    """
    
    html_file_path = os.path.join(output_dir, "report.html")
    with open(html_file_path, 'w') as html_file:
        html_file.write(html_content)

# Main execution
if args.cve:
    pocs = fetch_pocs_for_cve(args.cve)
    if pocs:
        for poc in pocs:
            print(Fore.CYAN + f"  {poc['html_url']}")
elif args.file and args.project:
    input_file = args.file
    project_name = args.project
    output_dir = create_output_directory(project_name)

    # Initialize counters and storage
    domains = set()
    ips = set()
    alive_domains = set()
    not_reachable_domains = set()
    domain_ip_mapping = {}
    open_ports_mapping = {}
    unique_ips = set()
    global cve_data
    cve_data = {}  # Initialize global cve_data

    # Read input file
    try:
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
                ip = socket.gethostbyname(domain)
                domain_ip_mapping[domain] = ip
                alive_domains.add(domain)
                unique_ips.add(ip)
                open_ports_mapping[domain] = []  # Initialize open ports for the domain
            except socket.error:
                not_reachable_domains.add(domain)

        # Logging results
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
        #print(Fore.YELLOW + "\n[+] Looking for CVEs")

        for ip in all_ips:
            try:
                response = requests.get(f"https://internetdb.shodan.io/{ip}")
                if response.status_code == 200:
                    data = response.json()
                    open_ports = data.get('ports', [])
                    cve_info = data.get('vulns', [])
                    hostnames = data.get('hostnames', [])
                    hostname_str = f"({'/'.join(hostnames)})" if hostnames else ''
                    
                    if open_ports:
                        print(Fore.GREEN + f"[+] {ip}{hostname_str} (Open Ports): {', '.join(map(str, open_ports))}")
                        # Update open ports mapping
                        for domain in domain_ip_mapping:
                            if domain_ip_mapping[domain] == ip:
                                open_ports_mapping[domain] = open_ports

                    if cve_info:
                        print(Fore.RED + f"[+] {ip}{hostname_str} (Vulnerabilities): {', '.join(cve_info)}")
                        fetch_pocs_and_print(ip, hostnames, cve_info)
                    else:
                        print(Fore.YELLOW + f"[+] {ip}{hostname_str} (No Vulnerabilities found)")
                else:
                    print(Fore.RED + f"[-] Failed to fetch data for {ip} with status code: {response.status_code}")
            except requests.RequestException as e:
                print(Fore.RED + f"[-] Error fetching data for {ip}: {e}")

        # Create JSON and HTML reports
        create_reports(output_dir, domain_ip_mapping, alive_domains, not_reachable_domains, cve_data, open_ports_mapping)

    except FileNotFoundError:
        print(Fore.RED + f"[-] Input file not found: {input_file}")
    except Exception as e:
        print(Fore.RED + f"[-] An error occurred: {e}")
else:
    parser.print_help()
