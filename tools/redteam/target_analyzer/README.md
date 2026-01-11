# Target Analyzer (Red Team)

**Purpose**: Perform passive reconnaissance on targets for authorized engagements.
Resolves hostnames to IPs, performs reverse DNS lookups, infers services from port listings, and assigns preliminary risk levels.

This tool is read-only and performs no active network scanning. It uses only DNS resolution and public naming conventions.

## Usage

```bash
# Analyze from plaintext list (one target per line, optional :ports suffix)
python3 target_analyzer.py --in targets.txt --out analysis.csv

# Analyze from CSV (columns: target, ports)
python3 target_analyzer.py --in targets.csv --out analysis.csv
```

## Input Format

**Plaintext**:
```
10.0.0.1:22,80,443
example.com
192.168.1.5:3389
```

**CSV**:
```csv
target,ports
10.0.0.1,"22,80,443"
example.com,
```

## Output CSV

Columns: `target`, `type` (ipv4/hostname), `resolved_ip`, `reverse_dns`, `services` (inferred), `risk_level`, `timestamp`

## Authorization

This tool is designed for **authorized engagements only** in lab or contracted environments.
