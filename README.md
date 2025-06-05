# Log-Analyzer
# Log Analyzer for Security Events
This Python-based tool analyzes system log files to detect suspicious behavior such as brute force attacks, repeated failed login attempts, and invalid user access.

##  Features
- Parses system logs (e.g., `auth.log`, `secure.log`, `syslog`)
- Detects:
  - Failed SSH login attempts
  - Authentication failures
  - Invalid user access
- Groups and summarizes events by IP address and type
- Lists top offending IPs and activity types

##  Requirements
- Python 3.x
- No external libraries required

##  Installation
Clone this repository and navigate to the folder:
```bash
git clone https://github.com/infogramme/log-analyzer.git
cd log-analyzer

## Usage
```
python log_analyzer.py path/to/your/logfile.log

### Sample Output
```
Suspicious IPs Detected:
 - 192.168.0.2: 15 suspicious events
 - 10.10.10.1: 5 suspicious events

Event Breakdown:
 - Failed Login: 15 times
 - Invalid User: 3 times
 - Auth Failure: 2 times

 Disclaimer
This tool is intended for educational and internal security auditing purposes only. Do not use it on systems you do not own or have permission to audit.
