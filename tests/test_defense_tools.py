from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]


def test_ioc_normalizer(tmp_path: Path):
    inp = tmp_path / 'iocs.txt'
    inp.write_text('192.168.1.1\nEXAMPLE.COM\n4b825dc642cb6eb9a060e54bf8d69288fbee4904\n')
    out = tmp_path / 'iocs_norm.csv'
    script = ROOT / 'tools' / 'defense' / 'ioc_normalizer' / 'ioc_normalizer.py'
    import runpy
    import sys
    oldargv = sys.argv[:]
    sys.argv = [str(script), '--in', str(inp), '--out', str(out)]
    try:
        runpy.run_path(str(script), run_name='__main__')
    finally:
        sys.argv = oldargv
    assert out.exists()
    txt = out.read_text()
    assert 'ipv4' in txt
    assert 'domain' in txt


def test_alert_simulator(tmp_path: Path):
    out = tmp_path / 'alerts.csv'
    script = ROOT / 'tools' / 'defense' / 'alert_simulator' / 'alert_simulator.py'
    import runpy
    import sys
    oldargv = sys.argv[:]
    sys.argv = [str(script), '--count', '5', '--out', str(out)]
    try:
        runpy.run_path(str(script), run_name='__main__')
    finally:
        sys.argv = oldargv
    assert out.exists()
    txt = out.read_text()
    assert 'signature' in txt


def test_sigma_tester(tmp_path: Path):
    log = tmp_path / 'app.log'
    log.write_text('normal line\npowershell -enc evil\nother\n')
    spec = tmp_path / 'spec.json'
    spec.write_text(json.dumps({'match': 'powershell'}))
    out = tmp_path / 'matches.csv'
    script = ROOT / 'tools' / 'defense' / 'sigma_tester' / 'sigma_tester.py'
    import runpy
    import sys
    oldargv = sys.argv[:]
    sys.argv = [str(script), '--spec', str(spec), '--log', str(log), '--out', str(out)]
    try:
        runpy.run_path(str(script), run_name='__main__')
    finally:
        sys.argv = oldargv
    assert out.exists()
    assert 'powershell' in out.read_text()
