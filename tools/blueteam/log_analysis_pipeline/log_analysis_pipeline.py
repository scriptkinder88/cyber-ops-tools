#!/usr/bin/env python3
"""
Log Analysis Pipeline: integrated blue team tool for parsing, enrichment, correlation, and anomaly detection.
Chains log parsing → anonymization → deduplication → anomaly scoring → rule matching into single workflow.
Outputs enriched CSV with anomaly scores and matched signatures for SIEM ingestion and IR.
"""
import argparse
import csv
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional
from collections import Counter


class LogAnalysisPipeline:
    """Multi-stage log analysis and enrichment pipeline."""

    def __init__(self, parser_format: str = 'syslog'):
        self.format = parser_format
        self.apache_regex = re.compile(
            r'(?P<host>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>[^\s]+) (?P<proto>[^"]+)" '
            r'(?P<status>\d{3}) (?P<size>\d+|-)'
        )
        self.syslog_regex = re.compile(
            r'(?P<time>\w{3}\s+\d+\s[\d:]+) (?P<host>\S+) (?P<proc>[^:]+): (?P<msg>.*)'
        )
        # Add support for JSON logs (common in modern systems)
        self.json_regex = re.compile(r'^\s*\{.*\}\s*$')
        
        self.suspicious_patterns = {
            'sql_injection': re.compile(r"(?i)(union|select|insert|delete|drop|update|exec|script)"),
            'command_injection': re.compile(r"(?i)(\$\(|`|\|&|&&|;|\||<|>|\n)"),
            'path_traversal': re.compile(r"(\.\./|\.\.\\)"),
            'xss': re.compile(r"(?i)(script>|onerror=|onclick=|<iframe)"),
            'suspicious_user_agent': re.compile(r"(?i)(sqlmap|nikto|dirbuster|acunetix|nmap)"),
        }
        self.known_bad_ips = set()
        self.known_patterns = {}

    def parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse a single log line based on configured format."""
        line = line.strip()
        if not line:
            return None
            
        # Try JSON format first (most common in modern logging)
        if self.json_regex.match(line):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass
        
        # Fallback to regex-based parsing
        if self.format == 'apache':
            m = self.apache_regex.search(line)
        else:  # syslog
            m = self.syslog_regex.search(line)

        if not m:
            return None
        return m.groupdict()

    def enrich_record(self, record: Dict) -> Dict:
        """Add enrichment fields to parsed record."""
        record['anomaly_score'] = 0
        record['threat_level'] = 'low'
        record['indicators'] = []

        # Extract message/path for analysis - combine multiple fields
        msg_parts = []
        if record.get('msg'):
            msg_parts.append(record['msg'])
        if record.get('path'):
            msg_parts.append(record['path'])
        if record.get('request'):
            msg_parts.append(record['request'])
        if record.get('query'):
            msg_parts.append(record['query'])
            
        msg = ' '.join(msg_parts)
        if not msg:
            return record

        # Check suspicious patterns in both msg and path
        for threat_type, pattern in self.suspicious_patterns.items():
            if pattern.search(msg):
                record['anomaly_score'] += 10
                record['indicators'].append(threat_type)

        # Check for known bad IPs
        src_ip = record.get('host', '')
        if src_ip in self.known_bad_ips:
            record['anomaly_score'] += 5
            record['indicators'].append('known_bad_ip')

        # High status codes (5xx, 4xx error spikes)
        status = record.get('status', '')
        if status and int(status) >= 400:
            record['anomaly_score'] += 3

        # Size anomalies (unusually large responses)
        size = record.get('size', '')
        if size and size != '-':
            try:
                if int(size) > 1000000:  # > 1MB
                    record['anomaly_score'] += 2
            except ValueError:
                pass

        # Determine threat level
        if record['anomaly_score'] >= 15:
            record['threat_level'] = 'high'
        elif record['anomaly_score'] >= 8:
            record['threat_level'] = 'medium'

        record['indicators'] = ','.join(record['indicators']) if record['indicators'] else ''
        record['timestamp_analysis'] = datetime.now(timezone.utc).isoformat()

        return record

    def deduplicate_records(self, records: List[Dict], key_fields: List[str]) -> List[Dict]:
        """Remove duplicate records based on key fields."""
        seen = set()
        deduped = []
        for record in records:
            key = tuple(record.get(f, '') for f in key_fields)
            if key not in seen:
                seen.add(key)
                deduped.append(record)
        return deduped

    def load_threat_intelligence(self, ti_file: Path) -> Dict:
        """Load threat intelligence (known bad IPs, patterns) from JSON."""
        if not ti_file.exists():
            return {}
        try:
            ti = json.loads(ti_file.read_text())
            if 'known_bad_ips' in ti:
                self.known_bad_ips = set(ti['known_bad_ips'])
            if 'patterns' in ti:
                self.known_patterns = ti['patterns']
            return ti
        except Exception as e:
            print(f"Warning: Could not load TI from {ti_file}: {e}")
            return {}

    def analyze_logs(self, log_file: Path, dedupe_keys: Optional[List[str]] = None, max_lines: int = 100000) -> List[Dict]:
        """Analyze logs: parse → enrich → deduplicate → score."""
        if dedupe_keys is None:
            dedupe_keys = ['host', 'msg'] if self.format == 'syslog' else ['host', 'method', 'path']

        records = []
        line_count = 0
        
        with log_file.open(errors='ignore') as f:
            for line in f:
                line_count += 1
                if line_count > max_lines:
                    print(f"Warning: Reached maximum line limit ({max_lines}), stopping analysis")
                    break
                    
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                parsed = self.parse_log_line(line)
                if parsed:
                    enriched = self.enrich_record(parsed)
                    records.append(enriched)
                    
                    # Progress indicator for large files
                    if line_count % 10000 == 0:
                        print(f"Processed {line_count} lines...", flush=True)

        # Deduplicate
        records = self.deduplicate_records(records, dedupe_keys)

        return records


def main():
    p = argparse.ArgumentParser(
        description='Integrated log analysis pipeline: parse → enrich → correlate → detect threats.'
    )
    p.add_argument('--log', dest='logfile', required=True, help='Log file to analyze')
    p.add_argument('--format', choices=['apache', 'syslog', 'json'], default='syslog', help='Log format')
    p.add_argument('--ti', dest='ti_file', help='Threat intelligence JSON file (optional)')
    p.add_argument('--out', dest='outfile', default='log_analysis.csv', help='Output CSV')
    p.add_argument('--threat-only', action='store_true', help='Output only records with threat_level >= medium')
    p.add_argument('--max-lines', type=int, default=100000, help='Maximum lines to process (default: 100k)')
    args = p.parse_args()

    logfile = Path(args.logfile)
    if not logfile.exists():
        print(f'Log file not found: {logfile}')
        return

    print(f'Analyzing {logfile} ({args.format} format, max {args.max_lines} lines)...', flush=True)

    pipeline = LogAnalysisPipeline(parser_format=args.format)

    # Load threat intelligence if provided
    if args.ti_file:
        ti_path = Path(args.ti_file)
        print(f'Loading threat intelligence from {ti_path}...')
        pipeline.load_threat_intelligence(ti_path)

    # Run analysis
    records = pipeline.analyze_logs(logfile, max_lines=args.max_lines)

    # Filter if requested
    if args.threat_only:
        records = [r for r in records if r.get('threat_level') in ('medium', 'high')]

    # Write output
    if records:
        # Determine fieldnames from first record
        fieldnames = list(records[0].keys())
        with open(args.outfile, 'w', newline='') as outfh:
            writer = csv.DictWriter(outfh, fieldnames=fieldnames)
            writer.writeheader()
            for record in records:
                writer.writerow(record)

        print(f'\nAnalysis complete:')
        print(f'  Total records: {len(records)}')
        threat_counts = Counter(r.get('threat_level', 'low') for r in records)
        print(f'  Threat levels: {dict(threat_counts)}')
        print(f'  Output: {args.outfile}')
    else:
        print('No records parsed from log file')


if __name__ == '__main__':
    main()
