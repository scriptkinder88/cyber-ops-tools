import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_script(script_path, argv):
    old_argv = sys.argv[:]
    sys.argv = [str(script_path)] + argv
    try:
        runpy.run_path(str(script_path), run_name='__main__')
    finally:
        sys.argv = old_argv


def test_log_parser(tmp_path):
    sample = tmp_path / 'sample_syslog.log'
    sample.write_text('Jan  1 00:00:00 host proc: Test message\n')
    script = ROOT / 'tools' / 'blueteam' / 'log_parser' / 'log_parser.py'
    out = tmp_path / 'out.csv'
    run_script(script, ['--file', str(sample), '--format', 'syslog', '--out', str(out)])
    assert out.exists()


def test_forensic_hasher(tmp_path):
    f = tmp_path / 'foo.txt'
    f.write_text('hello')
    script = ROOT / 'tools' / 'blueteam' / 'forensic_hasher' / 'forensic_hasher.py'
    out = tmp_path / 'hashes.csv'
    run_script(script, ['--path', str(tmp_path), '--out', str(out)])
    assert out.exists()


def test_engagement_planner(tmp_path):
    script = ROOT / 'tools' / 'redteam' / 'engagement_planner' / 'engagement_planner.py'
    out = tmp_path / 'plan.md'
    run_script(script, ['--target', 'example.com', '--scope', '1.2.3.0/24', '--author', 'tester', '--out', str(out)])
    assert out.exists()
