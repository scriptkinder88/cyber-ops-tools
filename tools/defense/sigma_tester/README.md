Sigma Tester (lightweight)

Purpose: apply minimal detection specs to plain text logs. Spec is a JSON object with `field` (e.g., "line") and `match` (substring) or simple `regex`.

Spec example:
```
{
  "title": "PowerShell",
  "field": "line",
  "match": "powershell"
}
```

Usage:
```
python3 sigma_tester.py --spec spec.json --log app.log --out matches.csv
```

This is local-only text scanning for detection testing; it does not execute any code from specs.
