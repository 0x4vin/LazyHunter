#!/usr/bin/python3
import asyncio
import aiohttp
import argparse
import json
import os
import sys
from datetime import datetime

# ANSI Color Palette
RED, GREEN, YELLOW, BLUE, CYAN, WHITE, RESET = (
    "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[96m", "\033[97m", "\033[0m"
)

BANNER = f"""
{CYAN}    __                      __  __            __             ____               
   / /   ____ _____  __  __/ / / /_  ______  / /____  _____ / __ \_________ 
  / /   / __ `/ _  |/ / / / /_/ / / / / __ \/ __/ _ \/ ___// /_/ / ___/ __ \\
 / /___/ /_/ / /_/ / /_/ / __  / /_/ / / / / /_/  __/ /   / ____/ /  / /_/ /
/_____/\__,_/\___, /\__, /_/ /_/\__,_/ / /_/\__/\___/_/   /_/   /_/   \____/ 
            /____//____/                                {WHITE}v2.0 - Elite Edition{RESET}
"""

class LazyHunterPro:
    def __init__(self, concurrency=10):
        self.cve_cache = {}
        self.results = []
        self.session = None
        self.semaphore = asyncio.Semaphore(concurrency) # Prevent API Rate-limiting

    async def fetch_json(self, url):
        async with self.semaphore:
            try:
                async with self.session.get(url, timeout=15) as response:
                    if response.status == 200:
                        return await response.json()
                    elif response.status == 429:
                        print(f"{RED}[!] Rate limit hit! Slowing down...{RESET}")
                        await asyncio.sleep(5)
                    return None
            except Exception as e:
                return None

    async def get_cve_details(self, cve_id):
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
        
        data = await self.fetch_json(f"https://cvedb.shodan.io/cve/{cve_id}")
        if data:
            details = {
                "summary": data.get("summary", "No description"),
                "cvss": data.get("cvss_v3", 0.0),
                "exploit_url": f"https://www.exploit-db.com/search?cve={cve_id.split('-')[1]}-{cve_id.split('-')[2]}"
            }
            self.cve_cache[cve_id] = details
            return details
        return {"summary": "N/A", "cvss": 0.0, "exploit_url": ""}

    def get_severity(self, score):
        if score >= 9.0: return f"{RED}[CRITICAL]{RESET}", "CRITICAL"
        if score >= 7.0: return f"{RED}[HIGH]{RESET}", "HIGH"
        if score >= 4.0: return f"{YELLOW}[MEDIUM]{RESET}", "MEDIUM"
        return f"{GREEN}[LOW]{RESET}", "LOW"

    async def scan_ip(self, ip):
        data = await self.fetch_json(f"https://internetdb.shodan.io/{ip}")
        if not data:
            print(f"{RED}[-] No data for {ip}{RESET}")
            return

        print(f"\n{BLUE}[+] Target Found: {CYAN}{ip}{RESET}")
        if data.get("hostnames"):
            print(f"{WHITE}    Hostnames: {GREEN}{', '.join(data['hostnames'])}{RESET}")

        ip_record = {
            "ip": ip,
            "hostnames": data.get("hostnames", []),
            "ports": data.get("ports", []),
            "vulns": []
        }

        # Async CVE Lookups
        tasks = [self.get_cve_details(cve) for cve in data.get("vulns", [])]
        cve_data_list = await asyncio.gather(*tasks)

        for cve_id, details in zip(data.get("vulns", []), cve_data_list):
            sev_color, level = self.get_severity(details['cvss'])
            print(f"    {sev_color} {WHITE}{cve_id:<15}{RESET} | {details['summary'][:60]}...")
            
            ip_record["vulns"].append({
                "id": cve_id,
                "severity": level,
                "cvss": details['cvss'],
                "exploit_search": details['exploit_url']
            })

        self.results.append(ip_record)

    def export_data(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        
        # 1. Full JSON Report
        json_file = f"lazyhunter_full_{timestamp}.json"
        with open(json_file, "w") as f:
            json.dump(self.results, f, indent=4)
        
        # 2. Nuclei Target List (IP:Port)
        nuclei_file = f"nuclei_targets_{timestamp}.txt"
        with open(nuclei_file, "w") as f:
            for res in self.results:
                for port in res['ports']:
                    f.write(f"{res['ip']}:{port}\n")

        print(f"\n{GREEN}[SUCCESS] Analysis Complete!{RESET}")
        print(f"{YELLOW}    [>] Full Report: {json_file}{RESET}")
        print(f"{YELLOW}    [>] Nuclei List: {nuclei_file} (Run: nuclei -l {nuclei_file}){RESET}")

    async def run(self, targets):
        async with aiohttp.ClientSession() as session:
            self.session = session
            print(f"{YELLOW}[*] Starting scan on {len(targets)} targets...{RESET}")
            await asyncio.gather(*(self.scan_ip(ip) for ip in targets))
            self.export_data()

if __name__ == "__main__":
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", help="Single IP address")
    parser.add_argument("-f", "--file", help="File containing IP addresses")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Max parallel requests")
    args = parser.parse_args()

    target_list = []
    if args.ip: target_list.append(args.ip)
    elif args.file:
        if os.path.exists(args.file):
            with open(args.file) as f: target_list = [l.strip() for l in f if l.strip()]
    
    if not target_list:
        print(f"{RED}[!] Error: No targets specified.{RESET}")
        sys.exit(1)

    hunter = LazyHunterPro(concurrency=args.concurrency)
    asyncio.run(hunter.run(target_list))
