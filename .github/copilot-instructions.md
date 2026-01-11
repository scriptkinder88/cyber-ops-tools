# Copilot Instructions for Cyber Ops Tools

## Project Overview
**Cyber Ops Tools** is a curated catalog of safe, responsible security helper scripts and documentation for red/blue team operations. The codebase emphasizes **defensive and operational tooling** across three main areas:
- **Defense tools** (`tools/defense/`): IOC normalization, alert simulation, detection testing
- **Blueteam tools** (`tools/blueteam/`): Log parsing, alert deduplication, forensic hashing, SIGMA detection generation
- **Infrastructure tools** (`tools/infra/`): CSV processing, Azure log normalization

## Architecture & Key Patterns

### Tool Structure
Every tool follows a consistent layout:
```
tools/<category>/<tool-name>/
  ├── README.md           # Usage, purpose, safety notes
  ├── metadata.yml        # Name, category, description, tested_os, intended_use, license
  └── <tool-name>.py      # Script (chmod +x, #!/usr/bin/env python3 shebang)
```

**Example from `tools/defense/ioc_normalizer/`**: Reads plaintext or CSV lists of IOCs, detects type (IPv4, IPv6, domain, MD5/SHA1/SHA256), normalizes formatting, writes canonical CSV.

### Red Team: Engagement Planning & Attack Automation
Red team tools focus on **planning, orchestration, and safe simulation** — NOT offensive payloads:
- **engagement_planner.py**: Generates Markdown scope/checklist from `--target`, `--scope`, `--objective` args. Includes "Rules of Engagement", authorization reminders, safe-stop conditions.
- **target_analyzer.py**: Passive reconnaissance tool. Performs DNS resolution, reverse DNS, service inference from ports, and risk scoring. Outputs CSV with `target`, `type`, `resolved_ip`, `reverse_dns`, `services`, `risk_level`.
- **attack_orchestrator.py**: Chains engagement phases via JSON configuration. Executes reconnaissance → simulation → analysis workflow. Config defines phases with tool names and I/O files; orchestrator runs sequentially and collects artifacts.
- **Pattern**: Use `argparse` → Markdown/JSON template rendering → file output. No code execution of payloads; purely documentation and workflow automation.
- **Orchestration workflow**:
  ```bash
  # 1. Generate engagement plan
  python3 engagement_planner.py --target example.com --scope "10.0.0.0/24" --out plan.md
  # 2. Analyze targets
  python3 target_analyzer.py --in targets.txt --out recon.csv
  # 3. Orchestrate multi-phase engagement
  python3 attack_orchestrator.py --config engagement.json --out ./artifacts/
  ```

### Blue Team: Log Analysis, Transcoding & Countermeasures
Blue team tools emphasize **evidence preservation, threat detection, and defensive automation**:

**Log Transcoding & Anonymization**:
- **log_parser.py**: Parses Apache/syslog formats into normalized CSV (columns: host, time, method, path, status, size). Extracts fields for downstream analysis.
- **log_anonymizer.py**: Masks PII in logs via regex substitution (IPv4 → `<IPV4>`, IPv6 → `<IPV6>`, email → `<EMAIL>`). Enables safe log sharing without exposure.
- **log_analysis_pipeline.py**: Integrated tool combining parse → enrich → correlate → detect. Scores logs for anomalies (SQL injection +10, path traversal +5, etc.). Detects threats via pattern matching and threat intelligence. Outputs single CSV with `anomaly_score`, `threat_level`, `indicators`.
- **Pattern**: Line-by-line transformation with regex cache (compile at module level), write to output file.

**Evidence & Threat Analysis**:
- **forensic_hasher.py**: Recursively SHA256/MD5 all files in a directory, outputs CSV for integrity verification and evidence cataloging during DFIR.
- **alert_deduper.py**: Removes duplicate alerts by key columns (timestamp, src_ip, dst_ip, signature). Reduces noise in SIEM pipelines.
- **Pattern**: DictReader/DictWriter for column preservation; deduplication via set of tuples.

**Detection Rules & Countermeasures**:
- **sigma_generator.py**: Generates Sigma YAML detection rules from JSON spec. Input: `{"title", "description", "logsource", "detection", "level"}`. Outputs valid Sigma rule for SIEM/Splunk ingestion.
- **countermeasure_generator.py**: Reads IOCs (CSV/JSON/plaintext) and auto-generates firewall rules (iptables), SIEM queries (Splunk), Sigma detection rules, and IR playbooks. Enables rapid response to active threats.
- **safe_logger.py**: Tails live logs, filters by keyword. Minimal safe design (no exfiltration, local file only). Simulates IR log monitoring.
- **Pattern**: JSON → YAML transcoding; read-only, stateless operations.

**Integrated Blue Team Workflow**:
```bash
# 1. Analyze logs for anomalies and threats
python3 log_analysis_pipeline.py --log apache.log --format apache --ti threat_intel.json --out threats.csv

# 2. Extract IOCs from threat analysis
python3 ioc_normalizer.py --in suspicious_ips.txt --out iocs_normalized.csv

# 3. Generate immediate defensive countermeasures
python3 countermeasure_generator.py --in iocs_normalized.csv --format all --out-prefix incident_response

# 4. Anonymize evidence for sharing
python3 log_anonymizer.py --in threats.csv --out evidence_sanitized.csv

# 5. Catalog evidence integrity
python3 forensic_hasher.py --path ./evidence/ --out evidence_hashes.csv
```

### Code Patterns

**Script Entry Points**
- All scripts use `if __name__ == '__main__': main()` pattern
- Use `argparse` for CLI arguments (no positional-only args; use `--in`, `--out`, etc.)
- `Path` from `pathlib` for file operations (e.g., `Path(args.inpath).exists()`)
- Return early on errors; print status on success

**CSV Operations**
- Use `csv.DictReader`/`csv.DictWriter` for round-trip data (preserves field order)
- Scripts handle missing/malformed input gracefully with `errors='ignore'` or validation
- Example: `ioc_normalizer.py` detects CSV headers (`'ioc' in lines[0].lower()`) or falls back to plaintext

**Type Detection & Validation**
- Use `re.compile()` for pattern matching (cache patterns at module level)
- Use `ipaddress.ip_address()` for IP validation (catches both v4/v6)
- Normalize case consistently: domains/hashes to `.lower()`, IPs unchanged

**Testing Pattern**
Tests use `runpy.run_path()` to execute scripts as modules with mock `sys.argv`:
```python
import runpy, sys
from pathlib import Path

oldargv = sys.argv[:]
sys.argv = [str(script), '--in', str(inp), '--out', str(out)]
try:
    runpy.run_path(str(script), run_name='__main__')
finally:
    sys.argv = oldargv
```
Assertions check file existence, expected content (grep for columns/keywords in output).

## Development Workflow

**Testing** (`pytest`):
- Run: `python -m pytest -q` (CI runs on Python 3.11)
- Tests use `tmp_path` fixture for isolated file I/O
- Tests verify output files exist and contain expected fields/keywords
- Location: `tests/test_*.py` (mirror tool categories: `test_defense_tools.py`, `test_azure_csv_pretty.py`)

**Linting** (`ruff`):
- Run: `ruff check .` (enforced in CI before tests)
- Minimal setup: Python 3.11, no type stubs required

**Dependencies**:
- Core: `pathlib`, `argparse`, `csv`, `re`, `ipaddress` (stdlib)
- Dev: `pytest`, `black`, `ruff`, `pyyaml`, `python-dateutil`
- Install: `pip install -r requirements.txt`

## Contributing Conventions

**Metadata Requirements** (every tool):
```yaml
name: tool-slug-name
category: defense|blueteam|infra|redteam|playbooks|automation
description: One-liner
tested_os: linux|windows|macos (or comma-separated)
intended_use: lab,testing,production,incident-response
license: MIT  # or other
```

**Responsible-Use Checklist**:
- [ ] No exploit payloads or binaries; reference upstream projects instead
- [ ] Include safe, sanitized test data (e.g., synthetic alerts, dummy logs)
- [ ] Add authorization/legal disclaimers in README for sensitive tools
- [ ] Ensure read-only operation where applicable (no persistent state, side effects)

## Key Files to Understand

| File | Purpose |
|------|---------|
| [README.md](README.md) | Project scope, repo layout, authorization rules |
| [CONTRIBUTING.md](CONTRIBUTING.md) | PR checklist, metadata requirements |
| [tools_catalog.md](tools_catalog.md) | Tool category definitions, naming conventions |
| [.github/workflows/tests.yml](.github/workflows/tests.yml) | CI: ruff → pytest on Python 3.11 |
| **Red Team: Engagement Automation** | |
| [tools/redteam/engagement_planner/](tools/redteam/engagement_planner/) | Reference: Markdown generation, scope/checklist templating |
| [tools/redteam/target_analyzer/](tools/redteam/target_analyzer/) | Reference: DNS resolution, service inference, risk assessment |
| [tools/redteam/attack_orchestrator/](tools/redteam/attack_orchestrator/) | Reference: JSON config orchestration, multi-phase workflow chaining |
| **Blue Team: Log Analysis** | |
| [tools/blueteam/log_parser/](tools/blueteam/log_parser/) | Reference: Apache/syslog regex parsing, CSV field extraction |
| [tools/blueteam/log_anonymizer/](tools/blueteam/log_anonymizer/) | Reference: Regex-based PII masking (IPv4, IPv6, email), line-by-line transcoding |
| [tools/blueteam/log_analysis_pipeline/](tools/blueteam/log_analysis_pipeline/) | Reference: Integrated parse→enrich→score→detect pipeline with anomaly scoring |
| [tools/blueteam/sigma_generator/](tools/blueteam/sigma_generator/) | Reference: JSON → YAML rule generation, detection automation |
| **Blue Team: Evidence & IR** | |
| [tools/blueteam/forensic_hasher/](tools/blueteam/forensic_hasher/) | Reference: Recursive hashing, evidence integrity cataloging |
| [tools/blueteam/alert_deduper/](tools/blueteam/alert_deduper/) | Reference: DictReader/DictWriter deduplication, noise reduction |
| [tools/blueteam/countermeasure_generator/](tools/blueteam/countermeasure_generator/) | Reference: IOC → firewall/SIEM/Sigma/playbook auto-generation |
| [tools/blueteam/safe-logger/](tools/blueteam/safe-logger/) | Reference: Live log tailing, safe monitoring (no exfiltration) |
| [tools/defense/alert_simulator/](tools/defense/alert_simulator/) | Reference: Synthetic alert generation for testing detection pipelines |
| [tests/test_defense_tools.py](tests/test_defense_tools.py) | Reference: runpy.run_path() integration testing pattern |

## Gotchas & Best Practices

1. **Argument names**: Use `--in` and `--out` (not positional args); map to `dest='inpath'`/`dest='outpath'` to avoid Python keywords.
2. **CSV round-trip**: Always use `DictWriter(fieldnames=reader.fieldnames)` to preserve order and columns.
3. **Graceful degradation**: Scripts should skip malformed lines (e.g., `if not line or line.startswith('#'): continue`).
4. **Path safety**: Use `Path.exists()` checks before reading; handle missing files with print + return.
5. **Tests are end-to-end**: They exercise full script execution, not unit tests of individual functions. Write integration assertions.
6. **Scope creep**: Tools are simple (100–150 lines typical). Complex logic belongs in playbooks or docs, not scripts.
7. **Red team automation**: 
   - Chain tools via JSON config (attack_orchestrator.py pattern)
   - No embedded offensive code; reference external vetted projects
   - Always include authorization reminders and rules of engagement
   - Generate engagement artifacts (plans, configs) not exploits
8. **Blue team transcoding**: 
   - Preserve data integrity through all transformations (DictReader → process → DictWriter)
   - Use regex caches for performance (compile at module level)
   - Implement anomaly scoring for threat prioritization
9. **Evidence handling**: 
   - Always hash files for integrity (forensic_hasher.py model)
   - Never modify originals; write to new outputs
   - Maintain chain of custody with timestamps
10. **Detection rules**: 
    - Keep Sigma rules minimal and portable (no tool-specific extensions)
    - Auto-generated rules should be marked `status: experimental`
    - Test rules before deploying to production
11. **Countermeasures**: Review all generated firewall/IR rules before deployment; test in isolated environment first.

## Advanced: Adding Orchestration to New Tools

When creating tools that chain multiple operations:

```python
# 1. Use JSON config pattern (like attack_orchestrator.py)
config = json.loads(Path('config.json').read_text())
phases = config.get('phases', [])

# 2. Execute phases sequentially with error handling
for phase in phases:
    success = run_phase(phase['name'], phase['command'])
    if not success and phase.get('required'):
        break

# 3. Collect and report all artifacts
print(f"Artifacts in: {output_dir}")
```

---

**Last updated**: January 11, 2026  
**Python version**: 3.11  
**See also**: [SECURITY.md](SECURITY.md), [DISCLAIMER.md](DISCLAIMER.md)
