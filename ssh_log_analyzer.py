"""SSH log analyzer: detect brute-force attempts and possible account compromise.

Reads an sshd auth log (the Debian/Ubuntu /var/log/auth.log format) and reports:

  1. Brute-force sources    - IPs with many failed logins inside a short time window
  2. Possible compromises   - a successful login from an IP that just failed repeatedly
  3. Username enumeration   - attempts against accounts that do not exist
  4. Summary statistics     - top attacking IPs and most-targeted usernames

Detections map to MITRE ATT&CK T1110 (Brute Force).

Usage:
    python3 ssh_log_analyzer.py sample_auth.log
    python3 ssh_log_analyzer.py sample_auth.log --threshold 5 --window 300 --csv report.csv

Standard library only, no installs needed.
"""

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# Example lines this parses:
#   Oct 28 10:14:03 web-server-01 sshd[2211]: Failed password for bob from 203.0.113.99 port 51234 ssh2
#   Oct 28 10:14:09 web-server-01 sshd[2211]: Failed password for invalid user admin from 203.0.113.45 port 40122 ssh2
#   Oct 28 10:14:30 web-server-01 sshd[2211]: Accepted password for bob from 203.0.113.99 port 51240 ssh2
LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<event>Failed|Accepted)\s+\w+\s+for\s+(?P<invalid>invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_log(path, year):
    """Yield dicts with time, event ('Failed'/'Accepted'), user, ip, invalid for each relevant line."""
    skipped = 0
    with open(path, errors="replace") as f:
        for raw in f:
            m = LINE_RE.match(raw)
            if not m:
                skipped += 1
                continue
            # Syslog timestamps have no year, so we supply one.
            ts = datetime.strptime(f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S")
            yield {
                "time": ts,
                "event": m["event"],
                "user": m["user"],
                "ip": m["ip"],
                "invalid": bool(m["invalid"]),
            }
    if skipped:
        print(f"(skipped {skipped} lines that were not login events)", file=sys.stderr)


def find_bruteforce(failed_by_ip, threshold, window):
    """Return {ip: (peak_failures, first_seen, last_seen)} for IPs whose failures
    reach `threshold` within any sliding window of `window` seconds."""
    flagged = {}
    span = timedelta(seconds=window)
    for ip, times in failed_by_ip.items():
        times.sort()
        left, best, best_range = 0, 0, None
        for right, t in enumerate(times):
            while t - times[left] > span:  # shrink window from the left
                left += 1
            count = right - left + 1
            if count > best:
                best, best_range = count, (times[left], t)
        if best >= threshold:
            flagged[ip] = (best, *best_range)
    return flagged


def find_compromises(events, threshold, window):
    """Flag an 'Accepted' login if the same IP had >= threshold failures in the
    `window` seconds before it. This is a classic sign a guessed password worked."""
    span = timedelta(seconds=window)
    recent_failures = defaultdict(list)
    alerts = []
    for e in sorted(events, key=lambda e: e["time"]):
        if e["event"] == "Failed":
            recent_failures[e["ip"]].append(e["time"])
        else:
            prior = [t for t in recent_failures[e["ip"]] if e["time"] - t <= span]
            if len(prior) >= threshold:
                alerts.append((e["time"], e["ip"], e["user"], len(prior)))
    return alerts


def print_section(title):
    print(f"\n{title}\n{'-' * len(title)}")


def main():
    p = argparse.ArgumentParser(description="Detect SSH brute-force activity in an auth log.")
    p.add_argument("logfile", help="path to an sshd auth log")
    p.add_argument("--threshold", type=int, default=5, help="failed logins that trigger an alert (default 5)")
    p.add_argument("--window", type=int, default=300, help="time window in seconds (default 300)")
    p.add_argument("--year", type=int, default=datetime.now().year, help="year to assume for log timestamps")
    p.add_argument("--csv", metavar="FILE", help="also write flagged IPs to a CSV file")
    args = p.parse_args()

    try:
        events = list(parse_log(args.logfile, args.year))
    except FileNotFoundError:
        sys.exit(f"Error: file not found: {args.logfile}")
    if not events:
        sys.exit("No SSH login events found. Is this an sshd auth log?")

    failed = [e for e in events if e["event"] == "Failed"]
    accepted = [e for e in events if e["event"] == "Accepted"]
    failed_by_ip = defaultdict(list)
    for e in failed:
        failed_by_ip[e["ip"]].append(e["time"])

    print("SSH LOG ANALYSIS REPORT")
    print("=======================")
    print(f"File: {args.logfile}")
    print(f"Period: {events[0]['time']} to {events[-1]['time']}")
    print(f"Events: {len(events)} ({len(failed)} failed, {len(accepted)} successful)")
    print(f"Rule: {args.threshold}+ failures within {args.window}s")

    brute = find_bruteforce(failed_by_ip, args.threshold, args.window)
    print_section(f"1. Brute-force sources ({len(brute)})")
    if brute:
        print(f"{'IP address':<16}{'Peak failures':<15}{'First seen':<22}Last seen")
        for ip, (n, first, last) in sorted(brute.items(), key=lambda kv: -kv[1][0]):
            print(f"{ip:<16}{n:<15}{first:%Y-%m-%d %H:%M:%S}   {last:%H:%M:%S}")
    else:
        print("None found.")

    comp = find_compromises(events, args.threshold, args.window)
    print_section(f"2. Possible account compromise ({len(comp)})  [HIGH PRIORITY]")
    if comp:
        for t, ip, user, n in comp:
            print(f"{t:%Y-%m-%d %H:%M:%S}  user '{user}' logged in from {ip} after {n} recent failures")
        print("Action: verify the login with the user, reset the password, review that session's activity.")
    else:
        print("None found.")

    invalid = Counter(e["user"] for e in failed if e["invalid"])
    print_section(f"3. Username enumeration ({len(invalid)} nonexistent usernames tried)")
    for user, n in invalid.most_common(5):
        print(f"{user:<15}{n} attempts")
    if not invalid:
        print("None found.")

    print_section("4. Top sources of failed logins")
    for ip, times in sorted(failed_by_ip.items(), key=lambda kv: -len(kv[1]))[:5]:
        print(f"{ip:<16}{len(times)} failures")

    if brute:
        print_section("Recommended mitigations")
        print("- Block flagged IPs (for example: sudo ufw deny from <ip>)")
        print("- Enforce SSH key authentication and set PasswordAuthentication no")
        print("- Install fail2ban to ban repeat offenders automatically")
        print("- Disable direct root login (PermitRootLogin no)")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ip", "peak_failures", "first_seen", "last_seen", "total_failures"])
            for ip, (n, first, last) in sorted(brute.items(), key=lambda kv: -kv[1][0]):
                w.writerow([ip, n, first.isoformat(), last.isoformat(), len(failed_by_ip[ip])])
        print(f"\nCSV written to {args.csv}")


if __name__ == "__main__":
    main()
