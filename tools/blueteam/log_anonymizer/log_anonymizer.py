#!/usr/bin/env python3
"""
Anonymize logs by masking IPv4, IPv6 and email addresses.
"""
import argparse
import re
from pathlib import Path

IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


def anonymize_line(line: str) -> str:
    line = IPV4_RE.sub('<IPV4>', line)
    line = IPV6_RE.sub('<IPV6>', line)
    line = EMAIL_RE.sub('<EMAIL>', line)
    return line


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--in', dest='infile', required=True)
    p.add_argument('--out', dest='outfile', default='anonymized.log')
    args = p.parse_args()

    infile = Path(args.infile)
    if not infile.exists():
        print('Input file not found:', infile)
        return

    with infile.open() as infh, open(args.outfile, 'w') as outfh:
        for line in infh:
            outfh.write(anonymize_line(line))
    print('Wrote', args.outfile)


if __name__ == '__main__':
    main()
