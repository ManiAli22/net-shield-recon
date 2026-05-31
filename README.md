# NetShield Recon & Automation Suite

An automated, defensive Python security application that bridges programmatic log analytics with active system firewall responses to mitigate brute-force authentication attacks in real-time.

## 🛠️ Security Framework Mapping
- **DIKW Framework:** Converts raw, unstructured authentication log dumps (Data) into parsed statistics (Information) to identify attack signatures (Knowledge) and enforce automatic firewall blocks (Wisdom).
- **CIA Triad Safeguards:** Optimizes system **Availability** by actively blocking resource-exhaustion and unauthorized authentication traffic.

## 📁 Repository Structure
```text
net-shield-recon/
├── main.py                 # Centralized CLI orchestration driver
├── .gitignore              # Prevents leakage of live telemetry/system logs
├── README.md               # Tool documentation
├── logs/
│   └── mock_auth.log       # Incident simulation logs
└── src/
    ├── __init__.py         # Python package initialization
    ├── firewall_mgr.py     # Live iptables rule injector (Requires Root)
    ├── log_parser.py       # Regex dictionary pattern analysis engine
    └── scanner.py          # Subprocess-driven wrapper for service discovery
