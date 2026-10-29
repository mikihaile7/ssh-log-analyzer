"""Generate a realistic fake SSH auth log for testing the analyzer.

macOS does not keep a Linux-style /var/log/auth.log, so this script creates
sample data in the same format an Ubuntu/Debian server would write.
All IP addresses come from the reserved documentation ranges (RFC 5737),
so none of them belong to real hosts.

Usage:
    python3 generate_sample_log.py                 # writes sample_auth.log
    python3 generate_sample_log.py -o my.log --seed 7
"""

import argparse
import random
from datetime import datetime, timedelta

HOSTNAME = "web-server-01"
LEGIT_USERS = ["alice", "bob", "carol", "dave"]
LEGIT_IPS = ["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"]
GUESSED_USERNAMES = ["admin", "root", "test", "ubuntu", "oracle", "postgres", "guest", "user"]


def line(ts, message):
    """Format one syslog-style line: 'Oct 29 03:12:45 host sshd[pid]: message'."""
    pid = random.randint(1000, 60000)
    # %e pads the day with a space (syslog style), e.g. 'Oct  5'
    stamp = ts.strftime("%b %e %H:%M:%S")
    return ts, f"{stamp} {HOSTNAME} sshd[{pid}]: {message}"


def port():
    return random.randint(30000, 65000)


def normal_activity(start, hours):
    """Employees logging in during working hours, with the occasional typo."""
    events = []
    for _ in range(hours * 3):
        ts = start + timedelta(seconds=random.randint(0, hours * 3600))
        user = random.choice(LEGIT_USERS)
        ip = LEGIT_IPS[LEGIT_USERS.index(user)]
        if random.random() < 0.12:  # mistyped password, then success
            events.append(line(ts, f"Failed password for {user} from {ip} port {port()} ssh2"))
            ts += timedelta(seconds=random.randint(5, 20))
        events.append(line(ts, f"Accepted password for {user} from {ip} port {port()} ssh2"))
    return events


def brute_force(start, ip, attempts, duration_s):
    """Rapid password guessing against common usernames from one IP."""
    events = []
    for _ in range(attempts):
        ts = start + timedelta(seconds=random.randint(0, duration_s))
        name = random.choice(GUESSED_USERNAMES)
        if name in LEGIT_USERS or name == "root":
            events.append(line(ts, f"Failed password for {name} from {ip} port {port()} ssh2"))
        else:
            events.append(line(ts, f"Invalid user {name} from {ip} port {port()}"))
            events.append(line(ts, f"Failed password for invalid user {name} from {ip} port {port()} ssh2"))
    return events


def compromise(start, ip, victim, failures):
    """Many failures against a real account followed by a successful login."""
    events = []
    ts = start
    for _ in range(failures):
        ts += timedelta(seconds=random.randint(2, 8))
        events.append(line(ts, f"Failed password for {victim} from {ip} port {port()} ssh2"))
    ts += timedelta(seconds=random.randint(2, 8))
    events.append(line(ts, f"Accepted password for {victim} from {ip} port {port()} ssh2"))
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--output", default="sample_auth.log")
    parser.add_argument("--seed", type=int, default=42, help="random seed for reproducible output")
    args = parser.parse_args()
    random.seed(args.seed)

    year = datetime.now().year
    day = datetime(year, 10, 28, 8, 0, 0)

    events = []
    events += normal_activity(day, hours=10)
    events += brute_force(day + timedelta(hours=2, minutes=14), "203.0.113.45", attempts=60, duration_s=240)
    events += brute_force(day + timedelta(hours=7, minutes=3), "198.51.100.77", attempts=25, duration_s=120)
    events += compromise(day + timedelta(hours=9, minutes=30), "203.0.113.99", victim="bob", failures=12)

    events.sort(key=lambda e: e[0])
    with open(args.output, "w") as f:
        for _, text in events:
            f.write(text + "\n")
    print(f"Wrote {len(events)} log lines to {args.output}")


if __name__ == "__main__":
    main()
