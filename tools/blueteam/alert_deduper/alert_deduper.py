#!/usr/bin/env python3
"""
Alert deduper: simple CSV deduplication by configured key columns.
"""
import argparse
import csv
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--in', dest='infile', required=True)
    p.add_argument('--out', dest='outfile', default='deduped.csv')
    p.add_argument('--key', nargs='+', default=['timestamp', 'src_ip', 'dst_ip', 'signature'], help='Columns to use as dedupe key')
    args = p.parse_args()

    infile = Path(args.infile)
    if not infile.exists():
        print('Input file not found:', infile)
        return

    seen = set()
    with infile.open() as infh, open(args.outfile, 'w', newline='') as outfh:
        reader = csv.DictReader(infh)
        writer = csv.DictWriter(outfh, fieldnames=reader.fieldnames)
        writer.writeheader()
        for row in reader:
            key = tuple(row.get(k, '') for k in args.key)
            if key in seen:
                continue
            seen.add(key)
            writer.writerow(row)
    print('Wrote', args.outfile)

if __name__ == '__main__':
    main()
