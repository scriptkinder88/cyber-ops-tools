#!/usr/bin/env python3
"""
azure_csv_pretty.py

Read a CSV exported from Azure (billing, activity logs, storage listings, etc.) and
render a compact, human-readable table or simple aggregated summary.

Features:
- Auto-detect delimiter (comma or semicolon)
- Try to normalize timestamps into ISO format
- Humanize byte-sized numeric fields (heuristic on column names)
- Optional grouping/aggregation (counts) by column
- Output modes: `table`, `csv` (normalized), `summary`

Usage examples:
  python3 azure_csv_pretty.py input.csv --mode table --rows 10
  python3 azure_csv_pretty.py input.csv --mode summary --group-by ResourceId

"""

import argparse
import csv
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

BYTE_KEYS = {'size', 'bytes', 'contentlength', 'content_length', 'length'}
TIME_FORMATS = [
    '%Y-%m-%dT%H:%M:%S.%fZ',
    '%Y-%m-%dT%H:%M:%SZ',
    '%Y-%m-%dT%H:%M:%S%z',
    '%Y-%m-%d %H:%M:%S',
    '%m/%d/%Y %H:%M:%S',
    '%d/%m/%Y %H:%M:%S',
    '%Y-%m-%d',
    '%m/%d/%Y',
]


def detect_delimiter(sample: str) -> str:
    # simple heuristic
    if sample.count(';') > sample.count(','):
        return ';'
    return ','


def try_parse_time(s: str) -> str:
    s = s.strip()
    if not s:
        return s
    # normalize trailing Z to +00:00 for fromisoformat
    s2 = s
    if s.endswith('Z'):
        s2 = s[:-1] + '+00:00'
    try:
        # Python's fromisoformat handles offsets
        return datetime.fromisoformat(s2).isoformat()
    except Exception:
        pass
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(s, fmt).isoformat()
        except Exception:
            continue
    # fallback: return original
    return s


def humanize_bytes(n: Any) -> str:
    # produce human-readable string from integer bytes or parseable input
    try:
        # if integer-like input provided, convert
        if isinstance(n, (int, float)):
            bytes_val = int(n)
        else:
            bytes_val = parse_bytes_to_int(str(n))
            if bytes_val is None:
                return str(n)
    except Exception:
        return str(n)

    x = bytes_val
    if x < 1024:
        return f"{x} B"
    for unit in ['KB', 'MB', 'GB', 'TB']:
        x = x / 1024.0
        if x < 1024:
            return f"{x:.2f} {unit}"
    return f"{x:.2f} PB"


def parse_bytes_to_int(s: str) -> int | None:
    """Parse human readable size like '1.5KB' or numeric strings into integer bytes.
    Returns None if parsing fails.
    """
    import re

    if s is None:
        return None
    t = str(s).strip()
    if not t:
        return None
    m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([kmgtp]?b)?$", t, re.I)
    if m:
        val = float(m.group(1))
        unit = (m.group(2) or '').lower()
        mul = 1
        if unit in ('kb', 'k'):
            mul = 1024
        elif unit in ('mb', 'm'):
            mul = 1024 ** 2
        elif unit in ('gb', 'g'):
            mul = 1024 ** 3
        elif unit in ('tb', 't'):
            mul = 1024 ** 4
        elif unit in ('pb', 'p'):
            mul = 1024 ** 5
        return int(val * mul)
    # fallback: try integer
    try:
        return int(float(t))
    except Exception:
        return None


def normalize_row(row: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in row.items():
        key = k.strip()
        val = v.strip()
        low = key.lower().replace(' ', '_')
        if any(t in low for t in ('time', 'date', 'timestamp')):
            val = try_parse_time(val)
        elif any(b in low for b in BYTE_KEYS):
            # produce both human-readable and numeric bytes column
            bytes_int = parse_bytes_to_int(val)
            if bytes_int is not None:
                out[f"{key}_bytes"] = str(bytes_int)
                val = humanize_bytes(bytes_int)
            else:
                val = humanize_bytes(val)
        else:
            # try numeric formatting
            try:
                if '.' in val:
                    fv = float(val)
                    val = f"{fv:,.2f}"
                else:
                    iv = int(val)
                    val = f"{iv:,}"
            except Exception:
                pass
        out[key] = val
    return out


def print_table(rows: List[Dict[str, str]], max_rows: int = 20, columns: List[str] = None, trim_width: int = 60):
    if not rows:
        print('No rows to display')
        return
    keys = list(rows[0].keys())
    if columns:
        # keep only columns that exist
        keys = [k for k in columns if k in keys]
    # calculate widths
    widths = {}
    for k in keys:
        max_val = max((len(r.get(k, '')) for r in rows[:max_rows]), default=0)
        widths[k] = max(len(k), min(max_val, trim_width))
    # header
    hdr = ' | '.join(k.ljust(widths[k]) for k in keys)
    sep = '-+-'.join('-' * widths[k] for k in keys)
    print(hdr)
    print(sep)
    for r in rows[:max_rows]:
        pieces = []
        for k in keys:
            v = r.get(k, '')
            if len(v) > widths[k]:
                v = v[: widths[k] - 3] + '...'
            pieces.append(v.ljust(widths[k]))
        line = ' | '.join(pieces)
        print(line)
    if len(rows) > max_rows:
        print(f"... ({len(rows)-max_rows} more rows) ...")


def summary_by(rows: List[Dict[str, str]], group_by: str):
    counts = {}
    for r in rows:
        key = r.get(group_by, '')
        counts[key] = counts.get(key, 0) + 1
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    print(f"Summary grouped by '{group_by}':\n")
    print('Value | Count')
    print('------+------')
    for v, c in items:
        print(f"{v} | {c}")


def select_columns(rows: List[Dict[str, str]], columns: List[str]) -> List[Dict[str, str]]:
    if not columns:
        return rows
    out = []
    for r in rows:
        nr = {k: r.get(k, '') for k in columns}
        out.append(nr)
    return out


def load_csv(path: Path, delimiter: str = None) -> List[Dict[str, str]]:
    text = path.read_text(errors='ignore')
    if delimiter is None:
        delimiter = detect_delimiter(text[:4096])
    reader = csv.DictReader(text.splitlines(), delimiter=delimiter)
    rows = [dict(r) for r in reader]
    return rows


def main():
    p = argparse.ArgumentParser(description='Pretty-print Azure CSV exports')
    p.add_argument('input', help='CSV input file')
    p.add_argument('--mode', choices=['table', 'csv', 'summary'], default='table')
    p.add_argument('--rows', type=int, default=20, help='Max rows to show in table mode')
    p.add_argument('--group-by', help='Column name to group by for summary')
    p.add_argument('--delimiter', help='Force delimiter (comma or semicolon)')
    p.add_argument('--columns', nargs='+', help='Select subset of columns to show')
    p.add_argument('--trim-width', type=int, default=60, help='Max column width when printing table')
    p.add_argument('--output', '-o', help='Write normalized CSV to this output file (mode csv or table)')
    args = p.parse_args()

    path = Path(args.input)
    if not path.exists():
        print('Input file not found:', path)
        sys.exit(2)

    rows_raw = load_csv(path, delimiter=args.delimiter)
    rows = [normalize_row(r) for r in rows_raw]
    if args.columns:
        rows = select_columns(rows, args.columns)

    if args.mode == 'table':
        print_table(rows, max_rows=args.rows, columns=args.columns, trim_width=args.trim_width)
        if args.output:
            # also write normalized CSV with selected columns
            import csv
            outp = Path(args.output)
            with outp.open('w', newline='') as fh:
                writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                for r in rows:
                    writer.writerow(r)
    elif args.mode == 'csv':
        # print normalized CSV to stdout
        if not rows:
            return
        if args.output:
            outp = Path(args.output)
            with outp.open('w', newline='') as fh:
                writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                for r in rows:
                    writer.writerow(r)
        else:
            writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
    elif args.mode == 'summary':
        gb = args.group_by
        if not gb:
            print('Please specify --group-by for summary mode')
            sys.exit(3)
        summary_by(rows, gb)


if __name__ == '__main__':
    main()
