# Countermeasure Generator (Blue Team)

**Purpose**: Automated incident response tool.
Reads attack indicators (IOCs) and generates immediate defensive outputs:
- Firewall rules (iptables/pf format)
- SIEM search queries (Splunk-compatible)
- Sigma detection rules (YAML)
- Incident response playbooks (Markdown)

Enables rapid response to active threats.

## Usage

```bash
# Generate all countermeasures from IOC list
python3 countermeasure_generator.py --in iocs.csv --out-prefix incident_response

# Generate only firewall rules
python3 countermeasure_generator.py --in indicators.txt --format firewall --out-prefix fw

# Generate only SIEM queries
python3 countermeasure_generator.py --in attackers.csv --format siem --out-prefix hunt
```

## Input Format

**CSV** (with type column):
```csv
indicator,type,description
192.168.1.100,ipv4,Attacker C2
evil.com,domain,Phishing domain
a1b2c3d4e5f6...,md5,Malware hash
```

**JSON**:
```json
[
  {"indicator": "10.0.0.50", "type": "ipv4", "source": "FireEye"},
  {"indicator": "cmd.exe /c whoami", "type": "command"}
]
```

**Plaintext**:
```
192.168.1.100
10.0.0.50
attacker.com
```

## Output Files

- `countermeasures_firewall.sh` — Executable iptables rules (REVIEW before running)
- `countermeasures_siem_queries.txt` — Splunk/SIEM queries for hunting
- `countermeasures_sigma_rules.yml` — Sigma YAML rules for detection
- `countermeasures_playbook.md` — IR playbook checklist

## Firewall Rules

Generated rules block indicators at network layer:
```bash
iptables -I INPUT -s 192.168.1.100 -j DROP
iptables -I FORWARD -s 192.168.1.100 -j DROP
```

**Before applying**: Review rules, test in isolated environment, coordinate with network team.

## Authorization

Use only in authorized incident response situations.
- Have written authorization to deploy countermeasures
- Test in isolated environment first
- Coordinate with network/security teams
- Document all actions taken
