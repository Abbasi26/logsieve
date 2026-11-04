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
                datetime(2026, 10, 21, 7, 0, 0, tzinfo=timezone.utc),
                datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc),
                ["event at 07:00", "event at 08:00", "event at 08:30", "event at 09:00"],
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
        cause_ids = [f.pattern.id for f in outcome.diagnosis.findings if f.pattern.confidence in {"high", "medium"}]
        assert "wu-name-not-resolved" not in cause_ids

    def test_window_cause_changes_with_window(self, tmp_path: Path):
        """Without a window the top cause is wu-name-not-resolved; with the 08:00-09:00 window that cause is gone."""
        records = [
            {"MESSAGE": "error 0x8024402C at 07:00", "timestamp": "2026-10-21T07:00:00Z"},
            {"MESSAGE": "wu-name-not-resolved at 07:00", "timestamp": "2026-10-21T07:00:00Z"},
            {"MESSAGE": "normal event at 08:30", "timestamp": "2026-10-21T08:30:00Z"},
        ]
        path = tmp_path / "test.jsonl"
        path.write_text(
            "\n".join(json.dumps(record) for record in records),
            encoding="utf-8",
        )
        # Without window: wu-name-not-resolved should be top cause
        outcome_no_window = execute(
            [path],
            parser="auto",
            since=None,
            until=None,
        )
        primary_no_window = outcome_no_window.diagnosis.primary
        assert primary_no_window is not None
        assert primary_no_window.pattern.id == "wu-name-not-resolved"

        # With 08:00-09:00 window: wu-name-not-resolved should be gone
        since = datetime(2026, 10, 21, 8, 0, 0, tzinfo=timezone.utc)
        until = datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc)
        outcome_with_window = execute(
            [path],
            parser="auto",
            since=since,
            until=until,
        )
        primary_with_window = outcome_with_window.diagnosis.primary
        if primary_with_window is not None:
            assert primary_with_window.pattern.id != "wu-name-not-resolved"

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

    def test_naive_vs_utc_offset_filtered_consistently(self, tmp_path: Path):
        """Naive event timestamps vs events with UTC offset (e.g. +02:00) are filtered consistently in UTC."""
        # 08:30 UTC = 10:30+02:00, both should be kept in window 08:00-09:00 UTC
        # 10:00 UTC = 12:00+02:00, both should be dropped
        records = [
            {"MESSAGE": "naive at 08:30", "timestamp": "2026-10-21T08:30:00"},  # naive = UTC
            {"MESSAGE": "offset at 10:30+02:00", "timestamp": "2026-10-21T10:30:00+02:00"},  # = 08:30 UTC
            {"MESSAGE": "naive at 10:00", "timestamp": "2026-10-21T10:00:00"},  # naive = UTC
            {"MESSAGE": "offset at 12:00+02:00", "timestamp": "2026-10-21T12:00:00+02:00"},  # = 10:00 UTC
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
        # Both 08:30 UTC events should be kept, both 10:00 UTC events should be dropped
        assert messages == ["naive at 08:30", "offset at 10:30+02:00"]

    def test_mixed_input_files_dated_and_undated(self, tmp_path: Path):
        """Mixed input files (one dated, one undated / different formats) as in spec section 5.2."""
        # File 1: dated events
        records1 = [
            {"MESSAGE": "file1 event at 07:00", "timestamp": "2026-10-21T07:00:00Z"},
            {"MESSAGE": "file1 event at 08:30", "timestamp": "2026-10-21T08:30:00Z"},
        ]
        path1 = tmp_path / "file1.jsonl"
        path1.write_text(
            "\n".join(json.dumps(record) for record in records1),
            encoding="utf-8",
        )

        # File 2: undated events
        records2 = [
            {"MESSAGE": "file2 event without timestamp"},
            {"MESSAGE": "file2 another undated event"},
        ]
        path2 = tmp_path / "file2.jsonl"
        path2.write_text(
            "\n".join(json.dumps(record) for record in records2),
            encoding="utf-8",
        )

        since = datetime(2026, 10, 21, 8, 0, 0, tzinfo=timezone.utc)
        until = datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc)
        outcome = execute(
            [path1, path2],
            parser="auto",
            since=since,
            until=until,
        )
        messages = [event.message for event in outcome.events]
        # Only file1 event at 08:30 should be kept; file2 undated events should be dropped with warning
        assert messages == ["file1 event at 08:30"]
        assert any("without a timestamp were excluded" in w for w in outcome.warnings)
        # Should count 2 undated events from file2
        warning_msg = [w for w in outcome.warnings if "without a timestamp were excluded" in w][0]
        assert "2 event(s)" in warning_msg


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