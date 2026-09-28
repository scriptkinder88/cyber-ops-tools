import tempfile
from pathlib import Path
from tools.infra.azure_csv_pretty import humanize_bytes, try_parse_time, normalize_row, select_columns


def test_humanize_bytes():
    assert humanize_bytes('512') == '512 B'
    assert 'KB' in humanize_bytes('2048')


def test_try_parse_time_iso():
    assert try_parse_time('2026-01-01T00:00:00Z').startswith('2026-01-01')


def test_normalize_row_and_select_columns():
    row = {'Timestamp': '2026-01-01T00:00:00Z', 'ContentLength': '1024', 'Name': 'example'}
    nr = normalize_row(row)
    assert 'Timestamp' in nr
    assert nr['ContentLength'].endswith('B') or 'KB' in nr['ContentLength']
    sel = select_columns([nr], ['Timestamp', 'Name'])
    assert list(sel[0].keys()) == ['Timestamp', 'Name']


def test_end_to_end():
    csvp = Path(tempfile.mkdtemp()) / 'sample.csv'
    csvp.write_text('Timestamp,ResourceId,ContentLength\n2026-01-01T00:00:00Z,/res/1,1024\n')
    # basic import and load
    from tools.infra.azure_csv_pretty import load_csv
    rows = load_csv(csvp)
    assert len(rows) == 1
    nr = normalize_row(rows[0])
    assert 'ContentLength' in nr
