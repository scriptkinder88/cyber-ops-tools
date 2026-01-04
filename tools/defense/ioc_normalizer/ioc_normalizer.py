#!/usr/bin/env python3
"""
Simple IOC normalizer.
Reads either a CSV with a column `ioc` or a plaintext list (one per line).
Detects type: ipv4, ipv6, domain, md5, sha1, sha256, unknown.
Outputs a CSV with columns: original, type, normalized
"""
import argparse
import csv
import re
from ipaddress import ip_address
from pathlib import Path

HASH_REGEX = {
    'md5': re.compile(r'^[0-9a-fA-F]{32}$'),
    'sha1': re.compile(r'^[0-9a-fA-F]{40}$'),
    'sha256': re.compile(r'^[0-9a-fA-F]{64}$'),
}

DOMAIN_RE = re.compile(r'^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')


def detect_type(s: str) -> str:
    s = s.strip()
    if not s:
        return 'empty'
    try:
        ip = ip_address(s)
        return 'ipv6' if ip.version == 6 else 'ipv4'
    except Exception:
        pass
    ls = s.lower()
    for h, rx in HASH_REGEX.items():
        if rx.match(ls):
            return h
    if DOMAIN_RE.match(s):
        return 'domain'
    return 'unknown'


def normalize(value: str, typ: str) -> str:
    if typ in ('md5', 'sha1', 'sha256'):
        return value.lower()
    if typ in ('ipv4', 'ipv6'):
        return value
    if typ == 'domain':
        return value.lower().strip('.')
    return value


def read_inputs(path: Path):
    text = path.read_text(errors='ignore')
    # if CSV detect header ioc
    lines = text.splitlines()
    if lines and ',' in lines[0] and 'ioc' in lines[0].lower():
        reader = csv.DictReader(lines)
        for r in reader:
            yield r.get('ioc', '').strip()
    else:
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            yield line


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--in', dest='inpath', required=True)
    p.add_argument('--out', dest='outpath', default='iocs_normalized.csv')
    args = p.parse_args()

    inp = Path(args.inpath)
    if not inp.exists():
        print('Input not found:', inp)
        return

    with open(args.outpath, 'w', newline='') as outfh:
        writer = csv.writer(outfh)
        writer.writerow(['original', 'type', 'normalized'])
        for v in read_inputs(inp):
            typ = detect_type(v)
            norm = normalize(v, typ)
            writer.writerow([v, typ, norm])
    print('Wrote', args.outpath)


if __name__ == '__main__':
    main()
