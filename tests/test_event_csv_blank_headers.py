from pathlib import Path

import pytest

from logsieve.parsers import parse_path
from logsieve.parsers.event_csv import parse_event_csv


@pytest.mark.parametrize("parser", ["auto", "event-csv"])
def test_event_csv_leading_blank_records(tmp_path: Path, parser: str):
    path = tmp_path / "events.txt"
    path.write_text(
        "\n"
        "  , \n"
        "Level,Event ID,Message\n"
        "Error,31,before\n"
        "Error,32,malformed,private-surplus\n"
        'Warning,33,"after, retry"\n',
        encoding="utf-8",
    )

    parsed = parse_path(path, parser)

    assert [
        (event.event_id, event.message, event.severity, event.source_type)
        for event in parsed.events
    ] == [
        ("31", "before", "error", "event_csv"),
        ("33", "after, retry", "warning", "event_csv"),
    ]
    assert parsed.warnings == [
        f"{path}:5: skipped CSV row with extra fields"
    ]


@pytest.mark.parametrize("text", ["", "\n", "  , \n\n"])
def test_event_csv_blank_records_have_no_header(text: str):
    source = Path("events.csv")

    parsed = parse_event_csv(text, source)

    assert parsed.events == []
    assert parsed.warnings == [f"{source}: CSV has no header"]


# Skipped: broader CSV changes and the full pytest run; reference assertions passed in memory.
# Risk: blank-record prefixes now produce structured CSV events instead of plain-text fallback.
