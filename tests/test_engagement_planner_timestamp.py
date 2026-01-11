from pathlib import Path
from datetime import datetime
import importlib.util


def load_module_from_path(path: Path):
    spec = importlib.util.spec_from_file_location('engagement_planner_mod', str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_engagement_planner_timestamp(tmp_path: Path):
    out = tmp_path / 'plan.md'
    script_path = Path(__file__).resolve().parents[1] / 'tools' / 'redteam' / 'engagement_planner' / 'engagement_planner.py'
    mod = load_module_from_path(script_path)
    # use the module's render_markdown
    mod.render_markdown('example.com', 'scope', ['obj1'], out, 'tester')
    txt = out.read_text()
    # find generated timestamp line
    lines = [line for line in txt.splitlines() if line.startswith('**Generated**')]
    assert lines, 'Generated timestamp not found'
    ts = lines[0].split(':', 1)[1].strip()
    # ensure timestamp is parseable and timezone-aware (+00:00)
    dt = datetime.fromisoformat(ts)
    assert dt.tzinfo is not None, 'Timestamp is not timezone-aware'
    # should be UTC
    assert dt.utcoffset().total_seconds() == 0
