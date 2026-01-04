Alert Deduper

Purpose: read an alerts CSV, deduplicate alerts by a chosen key (default: timestamp, src_ip, dst_ip, signature), and write a deduplicated CSV for analysts.

Usage:
```bash
python3 alert_deduper.py --in alerts.csv --out deduped.csv
```

This tool is safe and local-only; it performs CSV processing only.
