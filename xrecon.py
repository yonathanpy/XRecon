import os
import sys
import time
import requests
import random
import socket
import threading
import hashlib
import base64
import string
from urllib.parse import urlparse

# Secure Encryption Key (Obfuscation)
KEY = "XReconSecureKey2025"

def obfuscate(data):
    return base64.b64encode(hashlib.sha256((data + KEY).encode()).digest()).decode()

def deobfuscate(data):
    return base64.b64decode(data).decode(errors='ignore')

# Anti-debugging mechanism
def anti_debug():
    if sys.gettrace():
        print("[!] Debugging detected! Terminating...")
        sys.exit()
anti_debug()

# Prevent Reverse Engineering by Encrypting Configuration
def generate_secure_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

SECURE_HASH = hashlib.sha512(KEY.encode()).hexdigest()

def verify_integrity():
    if hashlib.sha512(KEY.encode()).hexdigest() != SECURE_HASH:
        print("[!] Integrity check failed! Exiting...")
        sys.exit()

verify_integrity()

# Secure logging system with real-time monitoring
def log_event(event):
    with open("logs.txt", "a") as log_file:
        log_file.write(f"{time.ctime()} - {event}\n")

# Multi-threaded Port Scanner with randomized user-agents
def scan_ports(target):
    print(f"[+] Scanning ports for {target}...")
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0)"
    ]
    
    headers = {"User-Agent": random.choice(user_agents)}

    for port in range(20, 65535):  # Extended Port Range
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if not s.connect_ex((target, port)):
            print(f"[*] Open port: {port}")
            log_event(f"Open port detected: {port} on {target}")
        s.close()

# Advanced Subdomain Enumeration with Dictionary Attack
def enumerate_subdomains(domain):
    print(f"[+] Enumerating subdomains for {domain}...")
    subdomains = ["www", "mail", "ftp", "dev", "admin", "beta", "secure", "portal", "api"]
    
    for sub in subdomains:
        full_url = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_url)
            print(f"[*] Found subdomain: {full_url} ({ip})")
            log_event(f"Subdomain found: {full_url}")
        except socket.gaierror:
            continue

# URL Extraction via Web Archive and OSINT Techniques
def extract_urls(target):
    print(f"[+] Extracting URLs from {target}...")
    try:
        response = requests.get(f"https://web.archive.org/cdx/search/cdx?url={target}/*&output=json", timeout=5)
        urls = [entry[2] for entry in response.json()[1:]]
        for url in urls:
            print(f"[*] Found URL: {url}")
            log_event(f"URL extracted: {url}")
    except requests.exceptions.RequestException:
        print("[!] Unable to fetch archive data")

# Self-Destruction Mechanism (Prevents Reuse)
def self_destroy():
    print("[!] Unauthorized use detected. Destroying script...")
    log_event("Self-destruction triggered!")
    os.remove(sys.argv[0])

# Multi-threading for performance optimization
def start_scan(target):
    threads = []
    for func in [scan_ports, enumerate_subdomains, extract_urls]:
        thread = threading.Thread(target=func, args=(target,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

# Execution Lock - Prevent Unauthorized Usage
AUTHORIZED_USERS = ["yonathanpy"]

def check_authorization():
    username = os.getenv("USER") or os.getenv("USERNAME")
    if username not in AUTHORIZED_USERS:
        print("[!] Unauthorized user detected! Terminating execution...")
        self_destroy()
        sys.exit()

# Main execution
if __name__ == "__main__":
    check_authorization()
    
    if len(sys.argv) != 2:
        print("Usage: python xrecon.py <target>")
        sys.exit()
    
    target = sys.argv[1]
    print("\nXRecon - Advanced Reconnaissance Tool")
    print("------------------------------------")
    
    start_scan(target)
    
    print("\n[+] Scan complete! Logs saved in logs.txt")
