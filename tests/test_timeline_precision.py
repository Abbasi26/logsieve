import json
from pathlib import Path

import pytest

from logsieve.pipeline import collect_events


@pytest.mark.parametrize("parser", ["auto", "journald"])
def test_collect_events_preserves_exact_timeline_order(tmp_path: Path, parser: str):
    records = [
        {"MESSAGE": "later", "timestamp": "2255-06-05T23:47:34.740994Z"},
        {"MESSAGE": "earlier", "timestamp": "2255-06-05T23:47:34.740993Z"},
        {"MESSAGE": "offset tie", "timestamp": "2255-06-06T00:47:34.740993+01:00"},
        {"MESSAGE": "naive tie", "timestamp": "2255-06-05T23:47:34.740993"},
        {"MESSAGE": "undated first"},
        {"MESSAGE": "undated second"},
    ]
    path = tmp_path / "collector.jsonl"
    path.write_text(
        "\n".join(json.dumps(record) for record in records),
        encoding="utf-8",
    )

    events, warnings = collect_events([path], parser)

    assert warnings == []
    assert [event.message for event in events] == [
        "earlier",
        "offset tie",
        "naive tie",
        "later",
        "undated first",
        "undated second",
    ]
    assert [event.order for event in events] == [1, 2, 3, 0, 4, 5]
    assert events[2].timestamp.tzinfo is None
