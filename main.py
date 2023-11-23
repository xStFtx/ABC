import asyncio
import logging
import nmap
import whois
import aiohttp
import ssl
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import geoip2.database
import argparse

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def get_ip(domain):
    try:
        ip_address = await asyncio.get_event_loop().getaddrinfo(domain, None)
        ip = ip_address[0][4][0]
        logging.info(f"Resolved IP for {domain}: {ip}")
        return ip
    except Exception as e:
        logging.error(f"Failed to resolve IP for {domain}: {e}")
        return None

async def whois_lookup(ip):
    try:
        w = await whois.whois(ip)
        logging.info(f"WHOIS for {ip}: \n{w.text}")
    except Exception as e:
        logging.error(f"WHOIS lookup failed for {ip}: {e}")

def nmap_scan(ip, ports):
    scanner = nmap.PortScanner()
    scanner.scan(ip, ports, '-v -A')
    logging.info(f"Nmap scan result for {ip}: {scanner[ip].all_tcp()}")

async def ssl_certificate_check(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        logging.info(f"SSL certificate for {domain}: \n{cert}")
    except Exception as e:
        logging.error(f"SSL certificate check failed for {domain}: {e}")

async def geoip_lookup(ip):
    try:
        with geoip2.database.Reader('/path/to/GeoLite2-City.mmdb') as reader:
            response = reader.city(ip)
            logging.info(f"GeoIP lookup for {ip}: {response.city.name}, {response.country.name}")
    except Exception as e:
        logging.error(f"GeoIP lookup failed for {ip}: {e}")

def directory_scan(domain):
    try:
        subprocess.run(["dirsearch", "-u", domain, "-e", "php,html,js"], check=True)
    except Exception as e:
        logging.error(f"Directory scan failed for {domain}: {e}")

async def banner_grabbing(ip, port):
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(b'\n')
        await writer.drain()
        banner = await reader.read(1024)
        logging.info(f"Banner for {ip}:{port} - {banner.decode().strip()}")
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        logging.error(f"Banner grabbing failed for {ip}:{port} - {e}")

async def subdomain_enumeration(domain):
    try:
        async with aiohttp.ClientSession() as session:
            with open('subdomains.txt', 'r') as file:
                for subdomain in file:
                    subdomain = subdomain.strip()
                    full_domain = f"{subdomain}.{domain}"
                    ip = await get_ip(full_domain)
                    if ip:
                        logging.info(f"Discovered subdomain: {full_domain} - {ip}")
    except Exception as e:
        logging.error(f"Subdomain enumeration failed for {domain} - {e}")

async def virustotal_check(domain):
    try:
        api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': api_key}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                result = await response.json()
                logging.info(f"VirusTotal check for {domain}: {result}")
    except Exception as e:
        logging.error(f"VirusTotal check failed for {domain} - {e}")

async def main(domains, max_threads=10):
    tasks = []
    for domain in domains:
        ip = await get_ip(domain)
        if ip:
            tasks.append(asyncio.create_task(whois_lookup(ip)))
            tasks.append(asyncio.create_task(nmap_scan(ip, '1-1024')))
            tasks.append(asyncio.create_task(ssl_certificate_check(domain)))
            tasks.append(asyncio.create_task(geoip_lookup(ip)))
            tasks.append(asyncio.create_task(subdomain_enumeration(domain)))
            tasks.append(asyncio.create_task(virustotal_check(domain)))
            # Adding banner grabbing for common ports
            for port in [22, 80, 443]:
                tasks.append(asyncio.create_task(banner_grabbing(ip, port)))

    await asyncio.gather(*tasks)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network Scanning Tool')
    parser.add_argument('domains', nargs='+', help='Domains to scan')
    args = parser.parse_args()

    asyncio.run(main(args.domains))
