import asyncio
import logging
import nmap
import whois
import ssl
import os
import argparse
import sqlite3
from datetime import datetime

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database setup function
def setup_database():
    with sqlite3.connect('scan_results.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scan_data 
                     (timestamp TEXT, domain TEXT, ip TEXT, type TEXT, result TEXT)''')
        conn.commit()

# Asynchronous function to get IP
async def get_ip(domain):
    try:
        ip_address = await asyncio.get_event_loop().getaddrinfo(domain, None)
        ip = ip_address[0][4][0]
        logging.info(f"Resolved IP for {domain}: {ip}")
        save_scan_data(domain, ip, "IP Resolution", "Success")
        return ip
    except Exception as e:
        logging.error(f"Failed to resolve IP for {domain}: {e}")
        save_scan_data(domain, None, "IP Resolution", str(e))
        return None

# Asynchronous WHOIS lookup
async def whois_lookup(domain, ip):
    try:
        w = await whois.whois(ip)
        logging.info(f"WHOIS for {domain}: \n{w.text}")
        save_scan_data(domain, ip, "WHOIS Lookup", w.text)
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {domain}: {e}")
        save_scan_data(domain, ip, "WHOIS Lookup", str(e))

# Asynchronous Nmap scan function
async def async_nmap_scan(ip, ports):
    try:
        scanner = nmap.PortScannerAsync()
        await scanner.scan(ip, ports, '-v -A')
        logging.info(f"Nmap scan result for {ip}: {scanner[ip].all_tcp()}")
        save_scan_data(ip, ip, "Nmap Scan", str(scanner[ip].all_tcp()))
    except Exception as e:
        logging.error(f"Nmap scan failed for {ip}: {e}")
        save_scan_data(ip, ip, "Nmap Scan", str(e))

# Asynchronous SSL certificate check
async def ssl_certificate_check(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        logging.info(f"SSL certificate for {domain}: \n{cert}")
        save_scan_data(domain, None, "SSL Certificate", cert)
    except Exception as e:
        logging.error(f"SSL certificate check failed for {domain}: {e}")
        save_scan_data(domain, None, "SSL Certificate", str(e))

# Save scan data to the database
def save_scan_data(domain, ip, scan_type, result):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect('scan_results.db') as conn:
        c = conn.cursor()
        c.execute("INSERT INTO scan_data VALUES (?, ?, ?, ?, ?)", (timestamp, domain, ip, scan_type, result))
        conn.commit()

# Main async function
async def main(domains, ports):
    setup_database()
    tasks = []

    for domain in domains:
        ip = await get_ip(domain)
        if ip:
            tasks.append(asyncio.create_task(whois_lookup(domain, ip)))
            tasks.append(asyncio.create_task(ssl_certificate_check(domain)))
            tasks.append(asyncio.create_task(async_nmap_scan(ip, ports)))

    await asyncio.gather(*tasks)

# Command line interface setup
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Advanced Network Scanning Tool')
    parser.add_argument('domains', nargs='+', help='Domains to scan')
    parser.add_argument('--ports', default='1-1024', help='Port range for Nmap scan')
    args = parser.parse_args()

    asyncio.run(main(args.domains, args.ports))
