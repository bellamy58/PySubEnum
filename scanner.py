
import requests
import argparse
import sys
import socket
import concurrent.futures
import re
import urllib3
from argparse import RawDescriptionHelpFormatter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# List of common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080, 8443]

def print_banner():
    banner = """
    #########################################################
    #                                                       #
    #          PYTHON PRO SUBDOMAIN SCANNER v3.2            #
    #          ---------------------------------            #
    #     Features: Passive Recon + DNS + Web Title         #
    #     Dev: Bekir58                                      #
    #                                                       #
    #########################################################
    """
    print(banner)

# --- PASSIVE GATHERING ---
def fetch_crtsh(domain):
    print(f"[*] Extracting data from: crt.sh...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0"}
    try:
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry['name_value']
                for sub in name_value.split("\n"):
                    subdomains.add(sub)
    except: pass
    return subdomains

def fetch_hackertarget(domain):
    print(f"[*] Extracting data from: HackerTarget...")
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains = set()
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            lines = response.text.split("\n")
            for line in lines:
                if "," in line:
                    sub = line.split(",")[0]
                    subdomains.add(sub)
    except: pass
    return subdomains

def fetch_alienvault(domain):
    print(f"[*] Extracting data from: AlienVault OTX...")
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subdomains = set()
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            if "passive_dns" in data:
                for entry in data["passive_dns"]:
                    sub = entry.get("hostname")
                    if sub:
                        subdomains.add(sub)
    except: pass
    return subdomains

# --- ACTIVE SCANNING ---
def scan_target(subdomain, scan_ports_flag):
    if "*" in subdomain: return None

    try:
        target_ip = socket.gethostbyname(subdomain)
    except:
        return None

    result = {
        "subdomain": subdomain,
        "ip": target_ip,
        "ports": [],
        "http_info": ""
    }

    # HTTP TITLE CHECK
    try:
        url = f"https://{subdomain}"
        try:
            r = requests.get(url, timeout=3, allow_redirects=True, verify=False)
        except:
            url = f"http://{subdomain}"
            r = requests.get(url, timeout=3, allow_redirects=True)
        
        # Title Regex
        if r.status_code:
            match = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
            title = match.group(1).strip()[:50] if match else "No Title"
            result["http_info"] = f"[{r.status_code}] {title}"
    except:
        result["http_info"] = "" 

    # PORT SCANNING
    if scan_ports_flag:
        for port in COMMON_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5) 
                if s.connect_ex((target_ip, port)) == 0:
                    result["ports"].append(port)
                s.close()
            except: pass

    return result

# --- MAIN ---
def main():
    print_banner()
    
    examples = """Examples:
    python scanner.py -d example.com
    python scanner.py -d example.com -c
    python scanner.py -d example.com -c -p -t 50
    python scanner.py -d example.com -c -p -o report.txt
    """
    
    parser = argparse.ArgumentParser(
        description="Advanced Subdomain Scanner",
        epilog=examples,
        formatter_class=RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-d", "--domain", help="Target Domain", required=True)
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-c", "--check", help="Perform Liveness Check (DNS+HTTP)", action="store_true")
    parser.add_argument("-p", "--ports", help="Scan common ports", action="store_true")
    parser.add_argument("-t", "--threads", help="Thread count (Default: 10)", type=int, default=10)
    
    args = parser.parse_args()
    
    # PHASE 1
    print("\n[ PHASE 1: PASSIVE RECONNAISSANCE ]")
    all_sub = set()
    all_sub.update(fetch_crtsh(args.domain))
    all_sub.update(fetch_hackertarget(args.domain))
    all_sub.update(fetch_alienvault(args.domain))
    
    if not all_sub:
        print("[-] No subdomains found.")
        sys.exit()

    print(f"\n[+] Total unique subdomains found: {len(all_sub)}")
    
    final_results = []

    # PHASE 2
    if args.check:
        print(f"\n[ PHASE 2: ACTIVE SCANNING (Threads: {args.threads}) ]")
        print("[*] Analysis starting...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_sub = {executor.submit(scan_target, sub, args.ports): sub for sub in all_sub}
            
            for future in concurrent.futures.as_completed(future_to_sub):
                data = future.result()
                if data:
                    out = f" [V] ALIVE: {data['subdomain']} ({data['ip']})"
                    if data['http_info']:
                        out += f" -> {data['http_info']}"
                    if args.ports and data['ports']:
                        out += f" | Ports: {data['ports']}"
                    
                    print(out)
                    final_results.append(data)
    else:
        for sub in sorted(all_sub):
            print(sub)
            final_results.append({"subdomain": sub})

    # SAVE
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for item in final_results:
                line = f"{item['subdomain']}"
                if 'ip' in item: line += f",{item['ip']}"
                if 'http_info' in item and item['http_info']: line += f",Web:{item['http_info']}"
                if 'ports' in item and item['ports']: line += f",Ports:{item['ports']}"
                f.write(line + "\n")
        print(f"\n[+] Results saved to '{args.output}'")

if __name__ == "__main__":
    main()
    