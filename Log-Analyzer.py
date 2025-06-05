import re
import sys
from collections import defaultdict, Counter

def parse_logs(filepath):
    suspicious_ips = defaultdict(list)
    patterns = [
        (re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"), "Failed Login"),
        (re.compile(r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)"), "Auth Failure"),
        (re.compile(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)"), "Invalid User")
    ]

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            for pattern, reason in patterns:
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    suspicious_ips[ip].append(reason)

    return suspicious_ips

def summarize(suspicious_ips):
    counter = Counter()
    for ip, events in suspicious_ips.items():
        counter[ip] = len(events)

    print("\nSuspicious IPs Detected:")
    for ip, count in counter.most_common(10):
        print(f" - {ip}: {count} suspicious events")

    print("\nEvent Breakdown:")
    reasons = Counter()
    for events in suspicious_ips.values():
        reasons.update(events)
    for reason, count in reasons.items():
        print(f" - {reason}: {count} times")

def main():
    if len(sys.argv) != 2:
        print("Usage: python log_analyzer.py <path_to_log_file>")
        return

    filepath = sys.argv[1]
    suspicious_ips = parse_logs(filepath)
    summarize(suspicious_ips)

if __name__ == "__main__":
    main()