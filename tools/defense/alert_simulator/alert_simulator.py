#!/usr/bin/env python3
"""
Generate synthetic alerts for testing.
"""
import argparse
import csv
import random
from datetime import datetime, timedelta, timezone

SIGNATURES = ['SuspiciousLogin', 'DataExfil', 'PortScan', 'MaliciousDownload']
SEVERITIES = ['low', 'medium', 'high', 'critical']


def rand_ip():
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--count', type=int, default=100)
    p.add_argument('--out', default='alerts.csv')
    p.add_argument('--start', default=None, help='Start timestamp (ISO or now)')
    args = p.parse_args()

    start = datetime.now(timezone.utc)
    if args.start:
        try:
            start = datetime.fromisoformat(args.start)
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    rows = []
    for i in range(args.count):
        ts = (start + timedelta(seconds=random.randint(0, 3600))).isoformat()
        sig = random.choice(SIGNATURES)
        sev = random.choice(SEVERITIES)
        src = rand_ip()
        dst = rand_ip()
        rows.append({'timestamp': ts, 'src_ip': src, 'dst_ip': dst, 'signature': sig, 'severity': sev, 'detail': f'synthetic-{i}'})

    with open(args.out, 'w', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=['timestamp','src_ip','dst_ip','signature','severity','detail'])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print('Wrote', args.out)


if __name__ == '__main__':
    main()
