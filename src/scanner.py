#!/usr/bin/env python3
import subprocess
import re

def run_network_scan(target_ip):
    """
    Programmatically executes an Nmap scan against a target IP
    and extracts open ports and services for defensive analysis.
    """
    print(f"[*] Launching defensive Nmap service scan against: {target_ip}")
    
    # Executing nmap -sV (Service version detection) safely through Python
    # This matches the core objective of your Information Security Lab 5
    command = ["nmap", "-sV", target_ip]
    
    try:
        # Run the system command and capture the text output
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        scan_output = result.stdout
        
        print("\n[+] --- Raw Scan Output Parsed Successfully ---")
        
        # Regular expression to catch lines like: 80/tcp open http Apache httpd 2.4.63
        port_pattern = r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)"
        
        open_ports = []
        for line in scan_output.splitlines():
            match = re.search(port_pattern, line)
            if match:
                port, service, version = match.groups()
                print(f"[!] ALERT: Found Open Port -> {port} ({service}) | Version: {version if version else 'Unknown'}")
                open_ports.append(port)
                
        if not open_ports:
            print("[+] No open TCP ports detected on the target network surface.")
            
        return open_ports

    except FileNotFoundError:
        print("[-] Error: 'nmap' utility is not installed or not found in system PATH.")
        return []
    except subprocess.CalledProcessError as e:
        print(f"[-] Error executing Nmap: {e.stderr}")
        return []
