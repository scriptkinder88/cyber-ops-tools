Forensic hasher

Purpose: recursively walk a directory, compute SHA256 and MD5 for each file and output a CSV suitable for triage or inventory.

Usage:
```bash
python3 forensic_hasher.py --path /mnt/forensics --out hashes.csv
```

This tool is read-only and safe; it only computes hashes and writes metadata.
