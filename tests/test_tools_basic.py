import runpy
import sys
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run_script(script_path, argv):
    old_argv = sys.argv[:]
    sys.argv = [str(script_path)] + argv
    try:
        runpy.run_path(str(script_path), run_name='__main__')
    finally:
        sys.argv = old_argv


def test_log_parser():
    # create sample syslog
    sample = ROOT / 'tools' / 'blueteam' / 'log_parser' / 'sample_syslog.log'
    sample.write_text('Jan  1 00:00:00 host proc: Test message\n')
    script = ROOT / 'tools' / 'blueteam' / 'log_parser' / 'log_parser.py'
    out = ROOT / 'tools' / 'blueteam' / 'log_parser' / 'out.csv'
    run_script(script, ['--file', str(sample), '--format', 'syslog', '--out', str(out)])
    assert out.exists()


def test_forensic_hasher():
    d = Path(tempfile.mkdtemp())
    f = d / 'foo.txt'
    f.write_text('hello')
    script = ROOT / 'tools' / 'blueteam' / 'forensic_hasher' / 'forensic_hasher.py'
    out = d / 'hashes.csv'
    run_script(script, ['--path', str(d), '--out', str(out)])
    assert out.exists()


def test_engagement_planner():
    script = ROOT / 'tools' / 'redteam' / 'engagement_planner' / 'engagement_planner.py'
    out = ROOT / 'tools' / 'redteam' / 'engagement_planner' / 'plan.md'
    run_script(script, ['--target', 'example.com', '--scope', '1.2.3.0/24', '--author', 'tester', '--out', str(out)])
    assert out.exists()


def test_alert_deduper():
    # use existing sample
    sample = ROOT / 'tools' / 'blueteam' / 'alert_deduper' / 'sample_alerts.csv'
    out = ROOT / 'tools' / 'blueteam' / 'alert_deduper' / 'deduped_test.csv'
    script = ROOT / 'tools' / 'blueteam' / 'alert_deduper' / 'alert_deduper.py'
    run_script(script, ['--in', str(sample), '--out', str(out)])
    assert out.exists()


def test_log_anonymizer():
    sample = ROOT / 'tools' / 'blueteam' / 'log_anonymizer' / 'sample.log'
    # ensure sample exists (created earlier)
    if not sample.exists():
        sample.write_text('2026-01-01 user@example.com 203.0.113.5\n')
    out = ROOT / 'tools' / 'blueteam' / 'log_anonymizer' / 'sample.anon.test.log'
    script = ROOT / 'tools' / 'blueteam' / 'log_anonymizer' / 'log_anonymizer.py'
    run_script(script, ['--in', str(sample), '--out', str(out)])
    assert out.exists()


def test_sigma_generator():
    spec = ROOT / 'tools' / 'blueteam' / 'sigma_generator' / 'sample_spec.json'
    out = ROOT / 'tools' / 'blueteam' / 'sigma_generator' / 'sample_rule_test.yml'
    script = ROOT / 'tools' / 'blueteam' / 'sigma_generator' / 'sigma_generator.py'
    run_script(script, ['--in', str(spec), '--out', str(out)])
    assert out.exists()
