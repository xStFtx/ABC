import asyncio
import logging
import nmap
import whois
import ssl
import argparse
import aiosqlite
import json
from datetime import datetime

class NetworkScanner:
    def __init__(self, config, domains, ports):
        self.domains = domains
        self.ports = ports
        self.config = config
        self.db_path = config['database_path']

    async def setup_database(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''CREATE TABLE IF NOT EXISTS scan_data 
                                (timestamp TEXT, domain TEXT, ip TEXT, type TEXT, result TEXT)''')
            await db.commit()

    async def scan(self):
        await self.setup_database()
        tasks = []
        for domain in self.domains:
            ip = await self.get_ip(domain)
            if ip:
                tasks.append(asyncio.create_task(self.whois_lookup(domain, ip)))
                tasks.append(asyncio.create_task(self.ssl_certificate_check(domain)))
                tasks.append(asyncio.create_task(self.async_nmap_scan(ip, self.ports)))
        await asyncio.gather(*tasks)

    async def get_ip(self, domain):
        try:
            ip_address = await asyncio.get_event_loop().getaddrinfo(domain, None)
            ip = ip_address[0][4][0]
            logging.info(f"Resolved IP for {domain}: {ip}")
            await self.save_scan_data(domain, ip, "IP Resolution", "Success")
            return ip
        except Exception as e:
            logging.error(f"Failed to resolve IP for {domain}: {e}")
            await self.save_scan_data(domain, None, "IP Resolution", str(e))
            return None

    async def whois_lookup(self, domain, ip):
        try:
            w = await whois.whois(ip)
            logging.info(f"WHOIS for {domain}: \n{w.text}")
            await self.save_scan_data(domain, ip, "WHOIS Lookup", w.text)
        except Exception as e:
            logging.error(f"WHOIS lookup failed for {domain}: {e}")
            await self.save_scan_data(domain, ip, "WHOIS Lookup", str(e))

    async def async_nmap_scan(self, ip, ports):
        try:
            scanner = nmap.PortScanner()
            await asyncio.to_thread(scanner.scan, ip, ports, '-v -A')
            if ip in scanner.all_hosts():
                scan_result = str(scanner[ip].all_tcp())
                logging.info(f"Nmap scan result for {ip}: {scan_result}")
                await self.save_scan_data(ip, ip, "Nmap Scan", scan_result)
            else:
                logging.info(f"No Nmap scan data found for {ip}")
                await self.save_scan_data(ip, ip, "Nmap Scan", "No data found")
        except Exception as e:
            logging.error(f"Nmap scan failed for {ip}: {e}, Type: {type(e)}, Args: {e.args}")
            await self.save_scan_data(ip, ip, "Nmap Scan", str(e))

    async def ssl_certificate_check(self, domain):
        try:
            cert = ssl.get_server_certificate((domain, 443))
            logging.info(f"SSL certificate for {domain}: \n{cert}")
            await self.save_scan_data(domain, None, "SSL Certificate", cert)
        except Exception as e:
            logging.error(f"SSL certificate check failed for {domain}: {e}")
            await self.save_scan_data(domain, None, "SSL Certificate", str(e))

    async def save_scan_data(self, domain, ip, scan_type, result):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("INSERT INTO scan_data VALUES (?, ?, ?, ?, ?)", 
                             (timestamp, domain, ip, scan_type, result))
            await db.commit()

if __name__ == "__main__":
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)

    logging.basicConfig(level=config.get('log_level', 'INFO'), 
                        format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(description='Advanced Network Scanning Tool')
    parser.add_argument('domains', nargs='+', help='Domains to scan')
    parser.add_argument('--ports', default='1-1024', help='Port range for Nmap scan')
    args = parser.parse_args()

    scanner = NetworkScanner(config, args.domains, args.ports)
    asyncio.run(scanner.scan())
