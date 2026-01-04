Blue Team — Log Parser

Purpose: small, safe utility to parse common log formats (syslog, Apache combined) and extract fields and simple indicators (IP, timestamp, URL, status).

Usage:
```bash
python3 log_parser.py --file /var/log/syslog --format syslog --out parsed.csv
```

This is a defensive tool — it only parses and summarizes logs locally and writes CSV output.
