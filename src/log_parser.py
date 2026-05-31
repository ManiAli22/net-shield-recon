#!/usr/bin/env python3
import re
from collections import defaultdict

def analyze_auth_logs(log_file_path, failure_threshold=3):
    """
    Parses a Linux auth.log file to detect potential brute-force attacks.
    Extracts IPs exceeding the defined threshold of failed login attempts.
    """
    # Dictionary to keep track of failed attempts per IP
    # Structure: { "192.168.1.100": 5 }
    failed_attempts = defaultdict(int)
    
    # Regular expression pattern to capture IP and status from the log line
    # Matches patterns like: Login attempt from 192.168.1.45 at 2025-09-09 09:00: failed
    log_pattern = r"Login attempt from (\S+) at .+: (\w+)"

    print(f"[*] Parsing log file: {log_file_path}")

    try:
        with open(log_file_path, "r") as file:
            for line in file:
                match = re.search(log_pattern, line)
                if match:
                    ip, status = match.groups()
                    if status.lower() == "failed":
                        failed_attempts[ip] += 1

    except FileNotFoundError:
        print(f"[-] Error: The file '{log_file_path}' does not exist.")
        return []
    except PermissionError:
        print(f"[-] Error: Permission denied reading '{log_file_path}'. Try using sudo.")
        return []

    # Filter out malicious IPs that crossed our threshold
    malicious_ips = []
    print("\n[+] --- Audit Summary ---")
    for ip, count in failed_attempts.items():
        if count >= failure_threshold:
            print(f"[!] ALERT: IP {ip} has {count} failed login attempts! (Threshold exceeded)")
            malicious_ips.append(ip)
        else:
            print(f"[*] Info: IP {ip} has {count} failed attempt(s).")
            
    if not malicious_ips:
        print("[+] No malicious brute-force signatures detected.")
        
    return malicious_ips
