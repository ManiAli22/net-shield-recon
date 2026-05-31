#!/usr/bin/env python3
import argparse
import sys
from src.scanner import run_network_scan
from src.log_parser import analyze_auth_logs
from src.firewall_mgr import apply_defense_rule

def main():
    # Centralized tool documentation engine
    parser = argparse.ArgumentParser(
        description="NetShield Recon & Automation Suite - A Defensive Security Tool"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available security modules")

    # 1. Recon Module CLI Configuration (Lab 5)
    scan_parser = subparsers.add_parser("scan", help="Perform a network reconnaissance scan")
    scan_parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR range")

    # 2. Log Audit Module CLI Configuration (Lab 1)
    audit_parser = subparsers.add_parser("audit", help="Analyze authentication logs for brute-force attacks")
    audit_parser.add_argument("-f", "--file", required=True, help="Path to auth log file (e.g., /var/log/auth.log)")

    # 3. Direct Firewall Rule Module Configuration (Lab 14)
    fw_parser = subparsers.add_parser("block", help="Manually inject an active iptables block rule")
    fw_parser.add_argument("-i", "--ip", required=True, help="IP address to drop traffic from")

    args = parser.parse_args()

    # Route execution based on terminal input commands
    if args.command == "scan":
        print(f"[*] Initializing network scanning module targeting: {args.target}")
        run_network_scan(args.target)
        
    elif args.command == "audit":
        print(f"[*] Scanning log architecture file: {args.file}")
        
        # Call the log parsing function and collect flagged malicious actors (Information Layer)
        flagged_ips = analyze_auth_logs(args.file)
        
        # If malicious targets are isolated, enforce active tactical defensive mitigations (Wisdom Layer)
        if flagged_ips:
            print(f"[+] Flagged IPs ready for defense automation: {flagged_ips}")
            print("[*] Transitioning to automated active block enforcement...")
            for ip in flagged_ips:
                apply_defense_rule(ip)
        else:
            print("[+] Active mitigation cycle skipped. Environment secure.")
        
    elif args.command == "block":
        print(f"[*] Forcing active defense mechanism against malicious actor: {args.ip}")
        apply_defense_rule(args.ip)
        
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
