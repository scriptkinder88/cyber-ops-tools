#!/usr/bin/env python3
"""
Lightweight sigma-like tester: apply simple JSON specs to logs and output matches.
"""
import argparse
import csv
import json
import re
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--spec', required=True)
    p.add_argument('--log', required=True)
    p.add_argument('--out', default='matches.csv')
    args = p.parse_args()

    spec = json.loads(Path(args.spec).read_text())
    match = spec.get('match')
    regex = spec.get('regex')
    field = spec.get('field', 'line')

    pattern = None
    if regex:
        pattern = re.compile(regex, re.I)

    out_rows = []
    with open(args.log) as fh:
        for i, line in enumerate(fh, 1):
            candidate = line if field == 'line' else ''
            ok = False
            if match and match.lower() in candidate.lower():
                ok = True
            if pattern and pattern.search(candidate):
                ok = True
            if ok:
                out_rows.append({'line_no': i, 'line': line.strip()})

    with open(args.out, 'w', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=['line_no','line'])
        writer.writeheader()
        for r in out_rows:
            writer.writerow(r)
    print('Wrote', args.out)


if __name__ == '__main__':
    main()
