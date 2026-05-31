#!/usr/bin/env python3
import subprocess
import os
import sys

def apply_defense_rule(ip_address):
    """
    Programmatically injects an iptables drop rule to block a malicious IP.
    Requires root privileges (sudo) to alter system firewall configurations.
    """
    # Defensive check: Ensure the script is executing with root privileges
    if os.geteuid() != 0:
        print(f"[-] Permission Denied: Cannot block {ip_address}. Must run as root (sudo).")
        return False

    print(f"[*] Initiating firewall isolation protocols against: {ip_address}")
    
    # Target command: iptables -A INPUT -s <IP> -j DROP
    # This matches Lab 1, Lab 2, and Lab 14 firewall blocking mechanics
    command = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
    
    try:
        # Check if rule already exists to avoid duplication
        check_cmd = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
        rule_exists = subprocess.run(check_cmd, capture_output=True)
        
        if rule_exists.returncode == 0:
            print(f"[*] Info: Active defense rule already deployed for malicious actor {ip_address}.")
            return True
            
        # Execute the active block rule
        subprocess.run(command, check=True)
        print(f"[!] SUCCESS: Packets from malicious actor {ip_address} are now actively DROPPED.")
        return True

    except subprocess.CalledProcessError as e:
        print(f"[-] Error updating firewall rules matrix: {e}")
        return False
