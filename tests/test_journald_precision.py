import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from logsieve.parsers.journald import parse_journald


@pytest.mark.parametrize(
    "field", ["__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP"]
)
@pytest.mark.parametrize(
    ("raw", "expected_iso"),
    [
        (0, "1970-01-01T00:00:00+00:00"),
        (-1, "1969-12-31T23:59:59.999999+00:00"),
        (9007199254740994, "2255-06-05T23:47:34.740994+00:00"),
        ("9007199254740994", "2255-06-05T23:47:34.740994+00:00"),
        ("253402300799999999", "9999-12-31T23:59:59.999999+00:00"),
        ("253402300800000000", None),
        ("invalid", None),
    ],
)
def test_journald_exact_microseconds_and_fallback(field, raw, expected_iso):
    parsed = parse_journald(
        json.dumps({
            "MESSAGE": "timestamp regression",
            field: raw,
            "timestamp": "2026-10-21T08:00:00Z",
        }),
        Path("collector.jsonl"),
    )

    expected = (
        datetime.fromisoformat(expected_iso)
        if expected_iso is not None
        else datetime(2026, 10, 21, 8, tzinfo=timezone.utc)
    )
    assert len(parsed.events) == 1
    assert parsed.events[0].timestamp == expected
    assert parsed.warnings == []

# Skipped: repository edits and pytest execution; reproduced float precision loss with Python.
# Risk: downstream timeline sorting still uses float seconds; its precision is outside this change.
