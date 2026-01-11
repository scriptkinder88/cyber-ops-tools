#!/usr/bin/env python3
"""
Attack Orchestrator: chains red team engagement phases into an automated workflow.
Orchestrates reconnaissance → enumeration → simulation → analysis.
Uses JSON config to define engagement phases and invokes corresponding tools.

Safe operation: only chains other tools; produces engagement artifacts (no direct exploitation).
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional


def load_config(path: Path) -> Dict:
    """Load engagement config from JSON."""
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    return json.loads(path.read_text())


def run_phase(phase_name: str, command: List[str]) -> bool:
    """Execute a phase command and return success/failure."""
    print(f"\n[{datetime.now(timezone.utc).isoformat()}] PHASE: {phase_name}")
    print(f"Command: {' '.join(command)}")
    try:
        result = subprocess.run(command, check=True, capture_output=False, text=True)
        print(f"✓ {phase_name} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {phase_name} failed with exit code {e.returncode}")
        return False
    except FileNotFoundError as e:
        print(f"✗ {phase_name} failed: command not found ({e})")
        return False


def orchestrate_engagement(config: Dict, output_dir: Path) -> bool:
    """
    Execute engagement phases in sequence according to config.
    
    Config structure:
    {
      "target": "example.com",
      "engagement_id": "ENG-001",
      "phases": [
        {
          "name": "reconnaissance",
          "tool": "target_analyzer.py",
          "input": "targets.txt",
          "output": "recon.csv"
        },
        ...
      ]
    }
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    engagement_id = config.get('engagement_id', 'unknown')
    
    print(f"\n{'='*60}")
    print(f"Engagement: {engagement_id}")
    print(f"Target: {config.get('target', 'N/A')}")
    print(f"Output: {output_dir}")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}")

    phases = config.get('phases', [])
    results = {}
    failed_phases = []

    for phase_config in phases:
        phase_name = phase_config.get('name', 'unknown')
        tool = phase_config.get('tool', '')
        input_file = phase_config.get('input', '')
        output_file = phase_config.get('output', '')

        if not tool:
            print(f"⚠ Phase '{phase_name}' has no tool defined, skipping")
            continue

        # Build command
        cmd = [sys.executable, tool]
        if input_file:
            cmd.extend(['--in', input_file])
        if output_file:
            output_path = output_dir / output_file
            cmd.extend(['--out', str(output_path)])

        # Add custom args if specified
        if 'args' in phase_config:
            cmd.extend(phase_config['args'])

        # Execute phase
        success = run_phase(phase_name, cmd)
        results[phase_name] = 'success' if success else 'failed'
        if not success:
            failed_phases.append(phase_name)

    # Print summary
    print(f"\n{'='*60}")
    print("Engagement Summary")
    print(f"{'='*60}")
    for phase_name, status in results.items():
        symbol = '✓' if status == 'success' else '✗'
        print(f"{symbol} {phase_name}: {status}")

    if failed_phases:
        print(f"\nFailed phases: {', '.join(failed_phases)}")
        print("Note: Some phases failed, but artifacts may still be available for analysis")

    print(f"Completed: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}")

    return len(failed_phases) == 0


def generate_sample_config(output_path: Path):
    """Generate a sample engagement config."""
    sample = {
        "engagement_id": "ENG-001",
        "target": "example.com",
        "description": "Sample red team engagement orchestration",
        "phases": [
            {
                "name": "reconnaissance",
                "description": "Target analysis and passive enumeration",
                "tool": "target_analyzer.py",
                "input": "targets.txt",
                "output": "recon.csv"
            },
            {
                "name": "alert_simulation",
                "description": "Simulate attack indicators for detection testing",
                "tool": "alert_simulator.py",
                "args": ["--count", "50"],
                "output": "attack_alerts.csv"
            },
            {
                "name": "ioc_normalization",
                "description": "Normalize detected IOCs for correlation",
                "tool": "ioc_normalizer.py",
                "input": "iocs.txt",
                "output": "iocs_normalized.csv"
            }
        ]
    }
    with open(output_path, 'w') as f:
        json.dump(sample, f, indent=2)
    print(f"Sample config written to {output_path}")


def main():
    p = argparse.ArgumentParser(
        description='Orchestrate red team engagement phases into an automated workflow.'
    )
    p.add_argument('--config', required=False, help='Engagement config (JSON)')
    p.add_argument('--out', dest='outdir', default='engagement_output', help='Output directory for artifacts')
    p.add_argument('--sample-config', dest='sample_config', help='Generate sample config at path and exit')
    args = p.parse_args()

    if args.sample_config:
        generate_sample_config(Path(args.sample_config))
        return

    if not args.config:
        print('Error: --config required (or --sample-config to generate template)')
        sys.exit(1)

    config_path = Path(args.config)
    try:
        config = load_config(config_path)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading config: {e}")
        sys.exit(1)

    output_dir = Path(args.outdir)
    success = orchestrate_engagement(config, output_dir)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
