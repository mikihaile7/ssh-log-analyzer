# SSH Log Analyzer

A Python command-line tool that reads an SSH authentication log and flags brute-force attacks,
possible account compromises, and username enumeration. Detections map to MITRE ATT&CK
T1110 (Brute Force).

## What it detects

| Detection | How it works |
|---|---|
| Brute-force source | An IP address with N or more failed logins inside a sliding time window |
| Possible compromise | A successful login from an IP that failed repeatedly just before it |
| Username enumeration | Failed logins for accounts that do not exist on the system |

It also prints summary statistics, recommended mitigations (ufw rules, key-only SSH, fail2ban),
and can export flagged IPs to CSV.

## Run it

Requires Python 3 only (no packages to install).

```bash
python3 generate_sample_log.py                  # creates sample_auth.log (fake data)
python3 ssh_log_analyzer.py sample_auth.log     # run the analysis
python3 ssh_log_analyzer.py sample_auth.log --threshold 10 --window 600 --csv report.csv
```

To analyze a real log, copy one from a Linux machine or VM (Ubuntu/Debian: `/var/log/auth.log`)
and pass its path. The log format must be the standard sshd syslog format.

## Sample data

macOS has no Linux-style `auth.log`, so `generate_sample_log.py` creates realistic fake
data: normal employee logins plus two brute-force sources and one successful compromise.
All IPs come from reserved documentation ranges (RFC 5737).

## Ideas to extend it

- Add GeoIP lookup for flagged IPs
- Detect logins at unusual hours or from new IPs per user
- Output an HTML report
- Parse Windows Security Event ID 4625 (failed logon) for a cross-platform version
- Run it on a real Ubuntu VM that is exposed to the internet and write up the findings
