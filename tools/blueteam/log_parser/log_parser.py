#!/usr/bin/env python3
"""
Simple, safe log parser that extracts basic fields from syslog and Apache combined logs.
Writes CSV with selected columns for downstream analysis.
"""
import argparse
import csv
import re
from pathlib import Path

APACHE_REGEX = re.compile(r'(?P<host>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>[^\s]+) (?P<proto>[^"]+)" (?P<status>\d{3}) (?P<size>\d+|-)')
SYSLOG_REGEX = re.compile(r'(?P<time>\w{3}\s+\d+\s[\d:]+) (?P<host>\S+) (?P<proc>[^:]+): (?P<msg>.*)')


def parse_apache(line):
    m = APACHE_REGEX.search(line)
    if not m:
        return None
    return m.groupdict()


def parse_syslog(line):
    m = SYSLOG_REGEX.search(line)
    if not m:
        return None
    return m.groupdict()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--file', required=True)
    p.add_argument('--format', choices=['apache', 'syslog'], default='syslog')
    p.add_argument('--out', default='parsed.csv')
    args = p.parse_args()

    path = Path(args.file)
    if not path.exists():
        print('File not found:', path)
        return

    with path.open() as fh, open(args.out, 'w', newline='') as outfh:
        writer = None
        for line in fh:
            if args.format == 'apache':
                rec = parse_apache(line)
            else:
                rec = parse_syslog(line)
            if not rec:
                continue
            if writer is None:
                writer = csv.DictWriter(outfh, fieldnames=list(rec.keys()))
                writer.writeheader()
            writer.writerow(rec)
    print('Wrote', args.out)


if __name__ == '__main__':
    main()
