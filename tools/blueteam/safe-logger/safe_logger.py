#!/usr/bin/env python3
"""Safe logger demo — tails a local file and prints matching lines.

This script is intentionally minimal and safe (no exfiltration, no remote access).
"""
import argparse
from pathlib import Path
import time


def tail_file(path: Path, keyword: str, lines: int):
    if not path.exists():
        print('File not found:', path)
        return
    with path.open() as f:
        # seek to end and read last N lines naively
        data = f.read().splitlines()
        for line in data[-lines:]:
            if keyword in line:
                print(line)
        # then follow new lines for demo
        f.seek(0, 2)
        try:
            while True:
                where = f.tell()
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    f.seek(where)
                else:
                    if keyword in line:
                        print(line, end='')
        except KeyboardInterrupt:
            print('\nStopped')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--file', required=True)
    p.add_argument('--keyword', default='ERROR')
    p.add_argument('--lines', type=int, default=10)
    args = p.parse_args()
    tail_file(Path(args.file), args.keyword, args.lines)
