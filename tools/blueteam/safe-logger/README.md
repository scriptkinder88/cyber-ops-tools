Safe logger (example)

Purpose: a sanitized helper that demonstrates safe, defensive tooling patterns for collecting local logs during incident response. This example intentionally uses only local, non-sensitive sample data.

Files:
- `safe_logger.py` — example script that tails a log file and prints lines containing a keyword (for demo only).
- `metadata.yml` — metadata for cataloging.

Usage (example):
```bash
python3 safe_logger.py --file sample.log --keyword ERROR --lines 10
```
