Sigma Generator

Purpose: take a small JSON input describing detection criteria and output a minimal Sigma YAML rule template.

Usage:
```bash
python3 sigma_generator.py --in spec.json --out rule.yml
```

This is a helper for rule authors and does not ship detection logic itself.
