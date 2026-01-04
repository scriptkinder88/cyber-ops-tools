# Cyber Ops Tools (Red & Blue Team)

Purpose
- A curated, responsible collection of operational activities, playbooks, and safe helper scripts used by red and blue teams.
- This repository is a catalog and toolbox scaffold — it intentionally contains documentation, configuration templates, and pointers to vetted projects rather than production offensive tooling.

Scope & rules
- All materials here are for use only in authorized, legal environments (lab, contract engagements, incident response with permission).
- Contributors must follow the `SECURITY.md` and `CONTRIBUTING.md` rules and confirm authorized use when adding new items.

Repository layout
- `tools/redteam/` — catalog entries and safe helper scripts for offensive security (no direct exploit code unless explicitly allowed and reviewed).
- `tools/blueteam/` — detection rules, logging playbooks, DFIR scripts, and response runbooks.
- `playbooks/` — step-by-step operational procedures (contain templates and checklists).
- `docs/` — onboarding, environment setup, and architecture notes.
- `scripts/` — small utilities (sanitized, non-malicious) to support workflow automation.
- `legal/` — disclaimers, acceptable-use, and contributor agreements.

Example: `azure_csv_pretty`
- Pretty-print or normalize Azure CSV exports (billing, activity logs, storage listings).
- Table view with column selection and width trimming:

```bash
python3 tools/infra/azure_csv_pretty.py tools/infra/sample_azure.csv --mode table --columns Timestamp ResourceId ContentLength --trim-width 50
```

- Write a normalized CSV with numeric byte columns (adds `<Column>_bytes` for byte fields):

```bash
python3 tools/infra/azure_csv_pretty.py tools/infra/sample_azure.csv --mode csv --columns Timestamp ResourceId ContentLength --output normalized.csv
```

This produces both human-friendly `ContentLength` and a machine-friendly `ContentLength_bytes` column in the output CSV.

How to use locally
1. Clone locally and review `DISCLAIMER.md` and `SECURITY.md`.
2. When adding tooling, include: short description, intended environment, tested OS, and authorization requirements.

Create a GitHub repo and push (example using `gh`):

```bash
cd /home/rikard
git init cyber-ops-tools
cd cyber-ops-tools
# copy files into this folder or create via repo
git add .
git commit -m "Initial scaffold: docs, templates, catalog"
# create remote (private recommended)
gh repo create my-org/cyber-ops-tools --private --description "Operational tooling catalog and playbooks" --confirm
git branch -M main
git push -u origin main
```

Contact / Maintainers
- Add maintainers in `MAINTAINERS.md` or use GitHub CODEOWNERS for teams.

Contribute
- See `CONTRIBUTING.md` for required metadata for tools and pull request checklist.

---

This repo emphasizes safety: do not add exploits or persistent malware artifacts without explicit, documented approval from authorized stakeholders.
