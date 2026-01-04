#!/usr/bin/env python3
"""
Recursive file hasher — computes SHA256 and MD5 for files and writes a CSV.
Read-only; intended for triage and evidence cataloging.
"""
import argparse
import csv
import hashlib
from pathlib import Path


def hash_file(path: Path):
    h256 = hashlib.sha256()
    hmd5 = hashlib.md5()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(8192), b''):
            h256.update(chunk)
            hmd5.update(chunk)
    return h256.hexdigest(), hmd5.hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--path', required=True)
    p.add_argument('--out', default='hashes.csv')
    args = p.parse_args()

    base = Path(args.path)
    if not base.exists():
        print('Path not found:', base)
        return

    with open(args.out, 'w', newline='') as outfh:
        writer = csv.writer(outfh)
        writer.writerow(['path', 'size', 'sha256', 'md5'])
        for f in base.rglob('*'):
            if f.is_file():
                try:
                    s256, s_md5 = hash_file(f)
                    writer.writerow([str(f), f.stat().st_size, s256, s_md5])
                except Exception as e:
                    print('Skipping', f, 'error:', e)
    print('Wrote', args.out)


if __name__ == '__main__':
    main()
