#!/usr/bin/env python3
"""
Target Analyzer: automated reconnaissance and analysis tool for red team engagements.
Reads target list (CSV or plaintext), performs passive analysis (DNS, WHOIS, port/service mapping),
and outputs structured CSV with findings for engagement planning.

Safe operation: reads only publicly available DNS/WHOIS data, no active scanning.
"""
import argparse
import csv
import socket
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional


# Regex patterns for common services/ports
SERVICE_PATTERNS = {
    'http': re.compile(r'80|http'),
    'https': re.compile(r'443|https|ssl'),
    'ssh': re.compile(r'22|ssh'),
    'smtp': re.compile(r'25|smtp'),
    'dns': re.compile(r'53|dns'),
    'ftp': re.compile(r'21|ftp'),
    'rpc': re.compile(r'111|rpc'),
    'netbios': re.compile(r'139|445|netbios'),
    'snmp': re.compile(r'161|snmp'),
    'rdp': re.compile(r'3389|rdp'),
}

COMMON_PORTS = [22, 25, 53, 80, 111, 139, 443, 445, 3389, 8080, 8443]


def resolve_dns(hostname: str) -> Optional[str]:
    """Attempt DNS resolution (passive, safe)."""
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except (socket.gaierror, socket.error):
        return None


def get_reverse_dns(ip: str) -> Optional[str]:
    """Attempt reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.error):
        return None


def infer_services_from_ports(ports: str) -> List[str]:
    """Infer likely services from port numbers (colon or comma separated)."""
    services = []
    port_list = re.split(r'[,:]', ports)
    for port_str in port_list:
        port_str = port_str.strip()
        if not port_str:
            continue
        for service, pattern in SERVICE_PATTERNS.items():
            if pattern.search(port_str):
                if service not in services:
                    services.append(service)
    return services


def analyze_target(target: str, ports: str = "") -> Dict[str, str]:
    """
    Analyze a target (hostname or IP) and return structured findings.
    Returns dict with keys: target, type, resolved_ip, reverse_dns, services, risk_level, timestamp
    """
    result = {
        'target': target,
        'type': 'unknown',
        'resolved_ip': '',
        'reverse_dns': '',
        'services': '',
        'risk_level': 'unknown',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }

    # Determine if target is IP or hostname
    try:
        socket.inet_aton(target)
        result['type'] = 'ipv4'
        result['resolved_ip'] = target
        rdns = get_reverse_dns(target)
        result['reverse_dns'] = rdns or ''
    except socket.error:
        result['type'] = 'hostname'
        ip = resolve_dns(target)
        result['resolved_ip'] = ip or ''

    # Infer services from ports
    if ports:
        services = infer_services_from_ports(ports)
        result['services'] = ','.join(services) if services else 'unknown'

    # Simple risk heuristic: common ports → elevated risk
    if ports:
        port_list = [p.strip() for p in re.split(r'[,:]', ports) if p.strip()]
        open_common = sum(1 for p in port_list if int(p) in COMMON_PORTS)
        if open_common >= 3:
            result['risk_level'] = 'high'
        elif open_common >= 1:
            result['risk_level'] = 'medium'
        else:
            result['risk_level'] = 'low'
    else:
        result['risk_level'] = 'unknown'

    return result


def read_targets(path: Path) -> List[tuple]:
    """
    Read targets from CSV or plaintext.
    CSV format: target, ports (optional)
    Plaintext: one target per line (IP or hostname)
    Returns list of (target, ports) tuples.
    """
    targets = []
    text = path.read_text(errors='ignore')
    lines = text.splitlines()

    if lines and ',' in lines[0] and ('target' in lines[0].lower() or 'ip' in lines[0].lower()):
        # CSV format
        reader = csv.DictReader(lines)
        for row in reader:
            target = row.get('target', '') or row.get('ip', '')
            ports = row.get('ports', '')
            if target.strip():
                targets.append((target.strip(), ports.strip()))
    else:
        # Plaintext format
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Try to parse "hostname:port1,port2" format
            if ':' in line:
                parts = line.split(':', 1)
                targets.append((parts[0].strip(), parts[1].strip()))
            else:
                targets.append((line, ''))

    return targets


def main():
    p = argparse.ArgumentParser(
        description='Analyze targets for red team engagement (passive reconnaissance only).'
    )
    p.add_argument('--in', dest='infile', required=True, help='Target list (CSV or plaintext)')
    p.add_argument('--out', dest='outfile', default='target_analysis.csv', help='Output CSV')
    args = p.parse_args()

    infile = Path(args.infile)
    if not infile.exists():
        print('Input file not found:', infile)
        return

    targets = read_targets(infile)
    if not targets:
        print('No targets found in', infile)
        return

    results = []
    for target, ports in targets:
        print(f'Analyzing {target}...', end=' ', flush=True)
        analysis = analyze_target(target, ports)
        results.append(analysis)
        print('done')

    # Write output CSV
    with open(args.outfile, 'w', newline='') as outfh:
        fieldnames = ['target', 'type', 'resolved_ip', 'reverse_dns', 'services', 'risk_level', 'timestamp']
        writer = csv.DictWriter(outfh, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)

    print(f'Wrote {args.outfile} ({len(results)} targets analyzed)')


if __name__ == '__main__':
    main()
