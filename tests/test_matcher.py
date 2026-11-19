import pytest
from logsieve.patterns.matcher import load_builtin, match_events
from logsieve.models import LogEvent
from datetime import datetime, timezone

MSI_CODES = ["1602", "1603", "1605", "1618", "1633", "1638", "1642"]


@pytest.fixture
def patterns():
    return load_builtin()


def _event(message: str, severity: str = "error", user: str = "") -> LogEvent:
    return LogEvent(
        timestamp=datetime.now(timezone.utc),
        severity=severity,
        source_file="AppEnforce.log",
        source_type="cmtrace",
        message=message,
        user=user,
    )


class TestMSIContextMatching:
    """MSI codes match only in exit-status phrasing, not in SIDs or thread IDs."""

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_matches_in_error_context(self, patterns, code):
        event = _event(f"Install failed with exit code {code}")
        hits = match_events([event], patterns)
        assert any(h.pattern.id.startswith("msi-") for h in hits), f"{code} should match in error context"

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_no_match_in_sid(self, patterns, code):
        # SID ending with the code
        event = _event("User logged on", user=f"S-1-5-21-1000-2000-3000-{code}")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), f"{code} in SID should not match"

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_no_match_in_thread_id(self, patterns, code):
        event = _event(f"Thread {code} started")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), f"thread {code} should not match"

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_no_match_in_build_number(self, patterns, code):
        event = _event(f"Build 10.0.{code}.1234 released")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), f"{code} in build number should not match"

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_no_match_in_info_event_without_keyword(self, patterns, code):
        # Even if severity is info, no keyword → no match
        event = _event(f"Process {code} completed", severity="info")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), f"info event with {code} but no keyword should not match"

    def test_no_match_thread_with_msi_suffix(self, patterns):
        event = _event("Thread 1603 started package.msi")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), "thread with .msi suffix should not match"

    def test_no_match_error_opening_thread(self, patterns):
        event = _event("Error opening thread 1603")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), "error opening thread should not match"

    def test_no_match_msi_in_version(self, patterns):
        event = _event("package.msi version 10.0.1603.1")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), "MSI in version string should not match"

    def test_no_match_sid_ending_with_code(self, patterns):
        event = _event("Failed for SID S-1-5-21-1000-2000-3000-1603")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), "SID ending with code should not match"

    def test_match_returning_keyword(self, patterns):
        event = _event("MainEngineThread is returning 1603")
        hits = match_events([event], patterns)
        assert any(h.pattern.id.startswith("msi-") for h in hits), "returning keyword should match"

    def test_match_terminated_with_exitcode(self, patterns):
        event = _event("terminated with exitcode: 1603")
        hits = match_events([event], patterns)
        assert any(h.pattern.id.startswith("msi-") for h in hits), "terminated with exitcode should match"

    def test_match_return_code(self, patterns):
        event = _event("Return code 1603")
        hits = match_events([event], patterns)
        assert any(h.pattern.id.startswith("msi-") for h in hits), "Return code should match"