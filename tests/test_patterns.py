from logsieve.models import LogEvent
from logsieve.patterns import load_builtin, load_patterns
from logsieve.patterns.matcher import LIBRARY_DIR


def _event(message: str, provider: str = "", event_id: str = "") -> LogEvent:
    return LogEvent(
        timestamp=None,
        severity="error",
        source_file="self.log",
        source_type="plain",
        message=message,
        provider=provider,
        event_id=event_id,
    )


def test_builtin_library_self_tests_and_sources():
    patterns = load_builtin()
    assert len(patterns) >= 50
    seen = set()
    for pattern in patterns:
        assert pattern.id not in seen
        seen.add(pattern.id)
        assert pattern.self_test
        assert pattern.confidence in {"high", "medium", "low"}
        assert pattern.severity in {"critical", "error", "warning", "info", "debug"}
        assert pattern.sources
        assert all(source.startswith("https://") for source in pattern.sources)
        event = _event(pattern.self_test, pattern.self_test_provider, pattern.self_test_event_id)
        assert pattern.matches(event, event.search_text()), pattern.id


def test_signed_decimals_and_uncertain_intune_code():
    patterns = {pattern.id: pattern for pattern in load_builtin()}
    winhttp = patterns["winhttp-name-not-resolved"]
    event = _event("client returned -2147012889")
    assert winhttp.matches(event, event.search_text())
    intune = patterns["intune-not-detected"]
    assert intune.uncertain is True
    event = _event("IME returned -2016345060")
    assert intune.matches(event, event.search_text())
    assert patterns["wu-event-20"].annotation is True
    assert patterns["wu-event-20"].uncertain is True


def test_duplicate_pattern_id_is_an_error(tmp_path):
    extra = tmp_path / "extra.yaml"
    extra.write_text(
        """
- id: wu-name-not-resolved
  title: duplicate
  codes: ["0x8024402C"]
  severity: error
  confidence: high
  sources: ["https://example.com/duplicate"]
  explanation: duplicate
  self_test: "0x8024402C"
""",
        encoding="utf-8",
    )
    from logsieve.errors import LogsieveError
    import pytest

    with pytest.raises(LogsieveError, match="duplicate pattern id"):
        load_patterns(LIBRARY_DIR, tmp_path)