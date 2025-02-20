import subprocess
import argparse
import requests
import socket
import threading

def get_subdomains(domain):
    subdomains = []
    wordlist = ["www", "mail", "ftp", "dev", "test", "staging", "api", "blog"]  # Extended wordlist
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            subdomains.append(subdomain)
        except socket.gaierror:
            pass
    return subdomains

def port_scan(target):
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 8080, 8443]  # Expanded port list
    open_ports = []
    
    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        if sock.connect_ex((target, port)) == 0:
            open_ports.append(port)
        sock.close()
    
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    return open_ports

def tech_stack(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        server = response.headers.get("Server", "Unknown")
        powered_by = response.headers.get("X-Powered-By", "Unknown")
        return {"Server": server, "X-Powered-By": powered_by}
    except requests.RequestException:
        return "Could not detect"

def main():
    parser = argparse.ArgumentParser(description="XRecon - Advanced Bug Bounty Reconnaissance Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    args = parser.parse_args()
    
    print("\n[XRecon] Starting Advanced Recon on:", args.domain)
    print("[+] Subdomains Found:", get_subdomains(args.domain))
    print("[+] Open Ports:", port_scan(args.domain))
    print("[+] Technology Stack:", tech_stack(args.domain))

if __name__ == "__main__":
    main()
