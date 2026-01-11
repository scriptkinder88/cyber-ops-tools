# Attack Orchestrator (Red Team)

**Purpose**: Automate multi-phase red team engagements by chaining reconnaissance, enumeration, simulation, and analysis tools.
Orchestrates workflows defined in JSON configuration; executes phases sequentially and collects artifacts.

This tool does **not** contain offensive code. It chains existing safe tools (alert simulation, IOC normalization, log parsing) into engagement workflows.

## Usage

```bash
# Generate sample config template
python3 attack_orchestrator.py --sample-config my_engagement.json

# Execute engagement workflow
python3 attack_orchestrator.py --config my_engagement.json --out ./engagement_artifacts/
```

## Config Format (JSON)

```json
{
  "engagement_id": "ENG-001",
  "target": "example.com",
  "description": "Authorized penetration test",
  "phases": [
    {
      "name": "reconnaissance",
      "description": "Target analysis",
      "tool": "target_analyzer.py",
      "input": "targets.txt",
      "output": "recon.csv"
    },
    {
      "name": "simulation",
      "description": "Generate synthetic attacks",
      "tool": "alert_simulator.py",
      "args": ["--count", "100"],
      "output": "attacks.csv"
    },
    {
      "name": "analysis",
      "description": "Normalize and analyze IOCs",
      "tool": "ioc_normalizer.py",
      "input": "discovered_iocs.txt",
      "output": "iocs_normalized.csv"
    }
  ]
}
```

## Output

- Executes phases sequentially (stops on phase failure by default)
- Collects all tool outputs in `--out` directory
- Prints summary report with phase status

## Authorization

**For authorized engagements only.** Ensure:
- Written authorization from target organization
- Engagement scope and rules of engagement documented
- Safe-stop conditions defined
