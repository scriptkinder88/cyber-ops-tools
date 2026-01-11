IOC Normalizer

Purpose: read a CSV or plain list of IOCs (IP, domain, hashes), detect IOC type, normalize formatting, and write a canonical CSV for ingestion.

Usage:

```bash
python3 ioc_normalizer.py --in iocs.txt --out iocs_normalized.csv
```

This tool is read-only and performs local parsing only (no external lookups).
