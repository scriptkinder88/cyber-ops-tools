from tools.infra.azure_csv_pretty import parse_bytes_to_int, try_parse_time
from datetime import datetime


def test_parse_bytes_various():
    assert parse_bytes_to_int('1024') == 1024
    assert parse_bytes_to_int('1KB') == 1024
    assert parse_bytes_to_int('1.5KB') == int(1.5 * 1024)
    assert parse_bytes_to_int('2 MB') == 2 * 1024 * 1024
    assert parse_bytes_to_int('') is None
    assert parse_bytes_to_int('n/a') is None


def test_try_parse_time_with_offset():
    s = '2026-01-01T12:34:56+02:00'
    dt = datetime.fromisoformat(try_parse_time(s))
    assert dt.hour == 12
    # ensure the returned string is parseable and has tzinfo
    assert dt.tzinfo is not None


def test_try_parse_time_z_suffix():
    s = '2026-01-01T00:00:00Z'
    out = try_parse_time(s)
    dt = datetime.fromisoformat(out)
    assert dt.tzinfo is not None
