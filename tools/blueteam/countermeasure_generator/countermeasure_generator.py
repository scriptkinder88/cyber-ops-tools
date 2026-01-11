#!/usr/bin/env python3
"""
Countermeasure Generator: automated defensive response tool for blue team.
Reads attack indicators (IOCs, log patterns, alert signatures) and generates:
  - Firewall rules (iptables/pf format)
  - SIEM search queries
  - Sigma detection rules
  - Response playbook templates

Produces immediate defensive output to respond to active threats.
"""
import argparse
import csv
import json
import yaml
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional


class CountermeasureGenerator:
    """Generate defensive rules and responses from attack indicators."""

    def __init__(self):
        self.indicators = []
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def load_indicators(self, path: Path) -> List[Dict]:
        """Load IOCs or attack indicators from CSV or JSON."""
        if path.suffix.lower() == '.json':
            return json.loads(path.read_text())
        elif path.suffix.lower() == '.csv':
            indicators = []
            with path.open() as f:
                reader = csv.DictReader(f)
                for row in reader:
                    indicators.append(row)
            return indicators
        else:
            # Treat as plaintext IOC list
            indicators = []
            for line in path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    indicators.append({'indicator': line, 'type': 'unknown'})
            return indicators

    def generate_firewall_rules(self, indicators: List[Dict]) -> str:
        """Generate iptables-style firewall rules from IP indicators."""
        rules = [
            "#!/bin/bash",
            "# Auto-generated firewall rules - review before applying",
            f"# Generated: {self.timestamp}",
            ""
        ]

        for ioc in indicators:
            ioc_type = ioc.get('type', '').lower()
            indicator = ioc.get('indicator', '') or ioc.get('ioc', '')

            if ioc_type in ('ipv4', 'ip'):
                rules.append(f"# Block IP: {indicator}")
                rules.append(f"iptables -I INPUT -s {indicator} -j DROP")
                rules.append(f"iptables -I FORWARD -s {indicator} -j DROP")
                rules.append("")

        rules.append("# Apply rules persistently (on Debian/Ubuntu):")
        rules.append("# sudo apt-get install iptables-persistent")
        rules.append("# sudo iptables-save > /etc/iptables/rules.v4")

        return "\n".join(rules)

    def generate_siem_query(self, indicators: List[Dict]) -> str:
        """Generate SIEM query (Splunk-compatible) from indicators."""
        queries = [
            "# Auto-generated SIEM queries",
            f"# Generated: {self.timestamp}",
            ""
        ]

        # Build search query
        ioc_conditions = []
        for ioc in indicators:
            ioc_type = ioc.get('type', '').lower()
            indicator = ioc.get('indicator', '') or ioc.get('ioc', '')

            if ioc_type in ('ipv4', 'ip'):
                ioc_conditions.append(f"(src_ip={indicator} OR dst_ip={indicator})")
            elif ioc_type == 'domain':
                ioc_conditions.append(f"domain={indicator}")
            elif ioc_type in ('md5', 'sha1', 'sha256', 'hash'):
                ioc_conditions.append(f"file_hash={indicator}")
            elif ioc_type == 'url':
                ioc_conditions.append(f"url={indicator}")

        if ioc_conditions:
            query = f"index=main ({' OR '.join(ioc_conditions)})"
            queries.append("# Splunk search:")
            queries.append(query)
            queries.append("")

        # Add threat hunting queries
        queries.append("# Hunt for lateral movement:")
        queries.append('index=main EventCode=4624 OR EventCode=4625 | stats count by src_ip, dst_ip, user')
        queries.append("")
        queries.append("# Hunt for process execution anomalies:")
        queries.append('index=main EventCode=1 | stats count by CommandLine, ParentImage')
        queries.append("")
        queries.append("# Hunt for network anomalies:")
        queries.append('index=main | stats count by src_ip, dst_ip | where count > 100')

        return "\n".join(queries)

    def generate_sigma_rules(self, indicators: List[Dict]) -> List[Dict]:
        """Generate Sigma detection rules from indicators."""
        rules = []

        for ioc in indicators:
            ioc_type = ioc.get('type', '').lower()
            indicator = ioc.get('indicator', '') or ioc.get('ioc', '')
            rule_id = f"auto-{hash(indicator) % 10000000}"

            if ioc_type in ('ipv4', 'ip', 'domain', 'url'):
                rule = {
                    'title': f'Detect connection to malicious {ioc_type}: {indicator}',
                    'id': rule_id,
                    'description': f'Auto-generated rule for {ioc_type} indicator',
                    'logsource': {'product': 'network_traffic'},
                    'detection': {
                        'selection': {'dest_ip': [indicator]} if ioc_type in ('ipv4', 'ip') else {'dest_domain': [indicator]},
                        'condition': 'selection'
                    },
                    'level': 'high',
                    'status': 'experimental'
                }
                rules.append(rule)

            elif ioc_type in ('md5', 'sha1', 'sha256', 'hash'):
                rule = {
                    'title': f'Detect malicious file: {indicator}',
                    'id': rule_id,
                    'description': f'Auto-generated rule for file hash {ioc_type}',
                    'logsource': {'product': 'process_creation'},
                    'detection': {
                        'selection': {f'{ioc_type}': [indicator]},
                        'condition': 'selection'
                    },
                    'level': 'critical',
                    'status': 'experimental'
                }
                rules.append(rule)

        return rules

    def generate_response_playbook(self, indicators: List[Dict]) -> str:
        """Generate incident response playbook template."""
        playbook = [
            "# Automated Incident Response Playbook",
            f"Generated: {self.timestamp}",
            "",
            "## Executive Summary",
            f"Detected {len(indicators)} indicators of compromise (IOCs).",
            "Follow this playbook to contain and eradicate the threat.",
            "",
            "## Containment (Immediate)",
            "- [ ] Block all IOCs at firewall/proxy",
            "- [ ] Isolate affected systems from network",
            "- [ ] Enable verbose logging on critical systems",
            "- [ ] Capture memory dumps of suspicious processes",
            "",
            "## Indicators to Block",
        ]

        for idx, ioc in enumerate(indicators, 1):
            ioc_type = ioc.get('type', 'unknown').upper()
            indicator = ioc.get('indicator', '') or ioc.get('ioc', '')
            playbook.append(f"  {idx}. [{ioc_type}] {indicator}")

        playbook.extend([
            "",
            "## Eradication (Next Steps)",
            "- [ ] Scan all systems for presence of IOCs",
            "- [ ] Remove malware and artifacts",
            "- [ ] Patch vulnerable systems",
            "- [ ] Rotate compromised credentials",
            "",
            "## Detection (Ongoing)",
            "- [ ] Deploy Sigma rules (see generated rules file)",
            "- [ ] Monitor SIEM for alert escalation",
            "- [ ] Hunt for related IOCs (C2, lateral movement)",
            "",
            "## Recovery",
            "- [ ] Restore systems from clean backups",
            "- [ ] Verify integrity of restored systems",
            "- [ ] Re-enable normal operations gradually",
            "- [ ] Continue monitoring for 30 days",
            "",
            "## Lessons Learned",
            "- [ ] Conduct post-incident review",
            "- [ ] Update detection rules",
            "- [ ] Update firewall rules",
            "- [ ] Train staff on threat indicators",
        ])

        return "\n".join(playbook)


    def generate_ids_rules(self, indicators: List[Dict]) -> str:
        """Generate IDS/IPS rules (Suricata/Snort compatible) from indicators."""
        rules = [
            "# Auto-generated IDS/IPS rules (Suricata/Snort compatible)",
            f"# Generated: {self.timestamp}",
            "# Apply with: suricata -c suricata.yaml -r rules_file",
            ""
        ]

        rule_id = 1000000
        for ioc in indicators:
            ioc_type = ioc.get('type', '').lower()
            indicator = ioc.get('indicator', '') or ioc.get('ioc', '')

            if ioc_type in ('ipv4', 'ip'):
                # Block traffic to/from malicious IP
                rules.append(f"drop ip {indicator} any -> any any (msg:\"Malicious IP {indicator}\"; sid:{rule_id};)")
                rules.append(f"drop ip any any -> {indicator} any (msg:\"Malicious IP {indicator}\"; sid:{rule_id+1};)")
                rule_id += 2
                
            elif ioc_type == 'domain':
                # Block DNS queries for malicious domain
                rules.append(f"alert udp any any -> any 53 (msg:\"Malicious domain {indicator}\"; content:\"{indicator}\"; nocase; sid:{rule_id};)")
                rule_id += 1
                
            elif ioc_type == 'url':
                # Block HTTP requests to malicious URLs
                rules.append(f"alert tcp any any -> any 80 (msg:\"Malicious URL {indicator}\"; content:\"{indicator}\"; http_uri; sid:{rule_id};)")
                rules.append(f"alert tcp any any -> any 443 (msg:\"Malicious URL {indicator}\"; content:\"{indicator}\"; http_uri; sid:{rule_id+1};)")
                rule_id += 2

        return "\n".join(rules)


def main():
    p = argparse.ArgumentParser(
        description='Generate defensive rules and response playbooks from attack indicators.'
    )
    p.add_argument('--in', dest='infile', required=True, help='IOC/indicator file (CSV, JSON, or plaintext)')
    p.add_argument('--out-prefix', dest='out_prefix', default='countermeasures', help='Output file prefix')
    p.add_argument('--format', choices=['firewall', 'siem', 'sigma', 'playbook', 'ids', 'all'], default='all',
                   help='Output format')
    args = p.parse_args()

    infile = Path(args.infile)
    if not infile.exists():
        print(f'Indicator file not found: {infile}')
        return

    print(f'Loading indicators from {infile}...')
    gen = CountermeasureGenerator()
    indicators = gen.load_indicators(infile)

    if not indicators:
        print('No indicators found')
        return

    print(f'Generating countermeasures for {len(indicators)} indicators...')

    # Generate outputs
    outputs = {}

    if args.format in ('firewall', 'all'):
        fw_output = gen.generate_firewall_rules(indicators)
        fw_path = Path(f'{args.out_prefix}_firewall.sh')
        fw_path.write_text(fw_output)
        fw_path.chmod(0o755)
        print(f'✓ Firewall rules: {fw_path}')
        outputs['firewall'] = fw_path

    if args.format in ('siem', 'all'):
        siem_output = gen.generate_siem_query(indicators)
        siem_path = Path(f'{args.out_prefix}_siem_queries.txt')
        siem_path.write_text(siem_output)
        print(f'✓ SIEM queries: {siem_path}')
        outputs['siem'] = siem_path

    if args.format in ('sigma', 'all'):
        sigma_rules = gen.generate_sigma_rules(indicators)
        sigma_path = Path(f'{args.out_prefix}_sigma_rules.yml')
        # Write YAML rules (one per line for SIEM ingestion)
        with sigma_path.open('w') as f:
            for rule in sigma_rules:
                f.write(yaml.dump(rule, sort_keys=False))
                f.write('---\n')
        print(f'✓ Sigma rules: {sigma_path}')
        outputs['sigma'] = sigma_path

    if args.format in ('playbook', 'all'):
        playbook_output = gen.generate_response_playbook(indicators)
        playbook_path = Path(f'{args.out_prefix}_playbook.md')
        playbook_path.write_text(playbook_output)
        print(f'✓ Response playbook: {playbook_path}')
        outputs['playbook'] = playbook_path

    if args.format in ('ids', 'all'):
        ids_output = gen.generate_ids_rules(indicators)
        ids_path = Path(f'{args.out_prefix}_ids_rules.rules')
        ids_path.write_text(ids_output)
        print(f'✓ IDS/IPS rules: {ids_path}')
        outputs['ids'] = ids_path

    print(f'\n✓ Countermeasures generated successfully')
    print(f'Review and test before deploying to production!')


if __name__ == '__main__':
    main()
