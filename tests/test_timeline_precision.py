import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from logsieve.pipeline import execute
from logsieve.pipeline import collect_events


class TestTimeWindow:
    @pytest.fixture
    def log_file(self, tmp_path: Path) -> Path:
        """Create a test log file with events at different times."""
        records = [
            {"MESSAGE": "event at 07:00", "timestamp": "2026-10-21T07:00:00Z"},
            {"MESSAGE": "event at 08:00", "timestamp": "2026-10-21T08:00:00Z"},
            {"MESSAGE": "event at 08:30", "timestamp": "2026-10-21T08:30:00Z"},
            {"MESSAGE": "event at 09:00", "timestamp": "2026-10-21T09:00:00Z"},
            {"MESSAGE": "event at 10:00", "timestamp": "2026-10-21T10:00:00Z"},
        ]
        path = tmp_path / "test.jsonl"
        path.write_text(
            "\n".join(json.dumps(record) for record in records),
            encoding="utf-8",
        )
        return path

    @pytest.fixture
    def log_file_with_no_timestamp(self, tmp_path: Path) -> Path:
        """Create a test log file with one event without a timestamp."""
        records = [
            {"MESSAGE": "event at 08:30", "timestamp": "2026-10-21T08:30:00Z"},
            {"MESSAGE": "event without timestamp"},
        ]
        path = tmp_path / "test.jsonl"
        path.write_text(
            "\n".join(json.dumps(record) for record in records),
            encoding="utf-8",
        )
        return path

    def _make_event(self, msg: str, ts: str | None) -> dict:
        return {"MESSAGE": msg, "timestamp": ts} if ts else {"MESSAGE": msg}

    @pytest.mark.parametrize(
        "since,until,expected_messages,description",
        [
            (
                datetime(2026, 10, 21, 8, 0, 0, tzinfo=timezone.utc),
                datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc),
                ["event at 08:00", "event at 08:30"],
                "window_inclusive_lower_exclusive_upper",
            ),
            (
                datetime(2026, 10, 21, 8, 0, 0, tzinfo=timezone.utc),
                datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc),
                ["event at 08:00", "event at 08:30"],
                "window_mid_range",
            ),
            (
                datetime(2026, 10, 21, 8, 0, 0, tzinfo=timezone.utc),
                None,
                ["event at 08:00", "event at 08:30", "event at 09:00", "event at 10:00"],
                "since_only",
            ),
            (
                None,
                datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc),
                ["event at 07:00", "event at 08:00", "event at 08:30"],
                "until_only",
            ),
            (
                None,
                None,
                ["event at 07:00", "event at 08:00", "event at 08:30", "event at 09:00", "event at 10:00"],
                "no_window",
            ),
        ],
    )
    def test_time_window_filters_events(
        self,
        log_file: Path,
        since: datetime | None,
        until: datetime | None,
        expected_messages: list[str],
        description: str,
    ):
        outcome = execute(
            [log_file],
            parser="auto",
            since=since,
            until=until,
        )
        messages = [event.message for event in outcome.events]
        assert messages == expected_messages, f"Failed for {description}"

    def test_no_timestamp_dropped_with_warning(self, log_file_with_no_timestamp: Path):
        since = datetime(2026, 10, 21, 8, 0, 0, tzinfo=timezone.utc)
        until = datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc)
        outcome = execute(
            [log_file_with_no_timestamp],
            parser="auto",
            since=since,
            until=until,
        )
        messages = [event.message for event in outcome.events]
        assert messages == ["event at 08:30"]
        assert any("without a timestamp were excluded" in w for w in outcome.warnings)

    def test_no_timestamp_not_dropped_without_window(self, log_file_with_no_timestamp: Path):
        outcome = execute(
            [log_file_with_no_timestamp],
            parser="auto",
            since=None,
            until=None,
        )
        messages = [event.message for event in outcome.events]
        assert messages == ["event at 08:30", "event without timestamp"]
        assert not any("without a timestamp were excluded" in w for w in outcome.warnings)

    def test_reversed_bounds_raises_error(self, log_file: Path):
        from logsieve.cli import main
        since = "2026-10-21T09:00:00Z"
        until = "2026-10-21T08:00:00Z"
        code = main(["diagnose", str(log_file), "--since", since, "--until", until])
        assert code == 2

    def test_window_excludes_cause_from_outside_window(self, tmp_path: Path):
        """A pattern code that appears only in the filtered-out event should not be a hit."""
        records = [
            {"MESSAGE": "error 0x8024402C at 07:00", "timestamp": "2026-10-21T07:00:00Z"},
            {"MESSAGE": "normal event at 08:30", "timestamp": "2026-10-21T08:30:00Z"},
        ]
        path = tmp_path / "test.jsonl"
        path.write_text(
            "\n".join(json.dumps(record) for record in records),
            encoding="utf-8",
        )
        since = datetime(2026, 10, 21, 8, 0, 0, tzinfo=timezone.utc)
        until = datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc)
        outcome = execute(
            [path],
            parser="auto",
            since=since,
            until=until,
        )
        # The 07:00 event with the error code should be filtered out
        messages = [event.message for event in outcome.events]
        assert messages == ["normal event at 08:30"]
        # The diagnosis should not include wu-name-not-resolved since it's in the filtered event
        cause_ids = [f.id for f in outcome.diagnosis.findings if f.confidence in {"high", "medium"}]
        assert "wu-name-not-resolved" not in cause_ids

    def test_inclusive_lower_bound(self, tmp_path: Path):
        """Event exactly at --since is kept."""
        records = [
            {"MESSAGE": "event at 08:00", "timestamp": "2026-10-21T08:00:00Z"},
            {"MESSAGE": "event at 08:30", "timestamp": "2026-10-21T08:30:00Z"},
        ]
        path = tmp_path / "test.jsonl"
        path.write_text(
            "\n".join(json.dumps(record) for record in records),
            encoding="utf-8",
        )
        since = datetime(2026, 10, 21, 8, 0, 0, tzinfo=timezone.utc)
        until = datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc)
        outcome = execute(
            [path],
            parser="auto",
            since=since,
            until=until,
        )
        messages = [event.message for event in outcome.events]
        assert messages == ["event at 08:00", "event at 08:30"]

    def test_exclusive_upper_bound(self, tmp_path: Path):
        """Event exactly at --until is dropped."""
        records = [
            {"MESSAGE": "event at 08:30", "timestamp": "2026-10-21T08:30:00Z"},
            {"MESSAGE": "event at 09:00", "timestamp": "2026-10-21T09:00:00Z"},
        ]
        path = tmp_path / "test.jsonl"
        path.write_text(
            "\n".join(json.dumps(record) for record in records),
            encoding="utf-8",
        )
        since = datetime(2026, 10, 21, 8, 0, 0, tzinfo=timezone.utc)
        until = datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc)
        outcome = execute(
            [path],
            parser="auto",
            since=since,
            until=until,
        )
        messages = [event.message for event in outcome.events]
        assert messages == ["event at 08:30"]


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