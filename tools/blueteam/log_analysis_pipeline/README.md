# Log Analysis Pipeline (Blue Team)

**Purpose**: Integrated incident response log analysis tool.
Parses logs (Apache/syslog), enriches with anomaly scores, deduplicates records, and detects threats using pattern matching and threat intelligence.

Single tool replaces the need to chain multiple tools for common IR workflows.

## Usage

```bash
# Analyze syslog with default settings
python3 log_analysis_pipeline.py --log /var/log/syslog --out analysis.csv

# Analyze Apache logs with threat intelligence
python3 log_analysis_pipeline.py --log /var/log/apache2/access.log --format apache --ti ti.json --out findings.csv

# Output only high/medium threat records
python3 log_analysis_pipeline.py --log auth.log --threat-only --out threats.csv
```

## Threat Intelligence Format (JSON)

```json
{
  "known_bad_ips": ["192.168.1.100", "10.0.0.50"],
  "patterns": {
    "ransomware": "\.locked|\.encrypted|HELP_RECOVER"
  }
}
```

## Output CSV

Columns: Original log fields + `anomaly_score`, `threat_level` (low/medium/high), `indicators`, `timestamp_analysis`

## Anomaly Scoring

- SQL injection patterns: +10 points
- Command injection: +10 points
- Path traversal: +5 points
- XSS patterns: +5 points
- HTTP error codes (4xx, 5xx): +3 points
- Large response (>1MB): +2 points
- Known bad IP: +5 points

**Threat Level**: low (<8), medium (8-14), high (≥15)

## Authorization

Use only on systems you own or have explicit permission to monitor.
