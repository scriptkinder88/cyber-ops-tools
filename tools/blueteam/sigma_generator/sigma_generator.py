#!/usr/bin/env python3
"""
Generate a minimal Sigma rule YAML from a small JSON spec.
Input example:
{
  "title": "Suspicious cmd",
  "description": "Detect suspicious command",
  "logsource": {"product": "windows"},
  "detection": {"selection": {"CommandLine": "*powershell*"}}
}
"""
import argparse
import json
import yaml
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--in', dest='infile', required=True)
    p.add_argument('--out', dest='outfile', default='rule.yml')
    args = p.parse_args()

    infile = Path(args.infile)
    if not infile.exists():
        print('Input file not found:', infile)
        return

    spec = json.loads(infile.read_text())
    # Minimal Sigma structure
    rule = {
        'title': spec.get('title', 'Generated Rule'),
        'id': spec.get('id', None) or None,
        'description': spec.get('description', ''),
        'logsource': spec.get('logsource', {}),
        'detection': spec.get('detection', {}),
        'level': spec.get('level', 'medium'),
    }
    Path(args.outfile).write_text(yaml.safe_dump(rule, sort_keys=False))
    print('Wrote', args.outfile)


if __name__ == '__main__':
    main()
