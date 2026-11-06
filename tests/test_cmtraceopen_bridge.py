"""Tests for the optional CMTrace Open backend.

The unit tests use a stand-in bridge script that prints fixed JSON in the shape of
cmtraceopen-parser's ParseResult, so they need no Rust toolchain. The last test runs
the real bridge only when LOGSIEVE_CMTRACEOPEN points at a built binary (the
cmtraceopen-bridge CI job sets it).
"""

from __future__ import annotations

import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from logsieve.cli import main
from logsieve.errors import LogsieveError
from logsieve.parsers import parse_path
from logsieve.parsers.cmtraceopen import BRIDGE_ENV, convert, find_bridge, parse_cmtraceopen

DEMO_LOGS = Path(__file__).resolve().parents[1] / "src" / "logsieve" / "demo_logs"

SAMPLE = {
    "entries": [
        {
            "id": 0,
            "lineNumber": 1,
            "message": "Content not found 0x87D00607 on 203.0.113.10",
            "component": "ContentAccess",
            "timestamp": 1792587800000,
            "timestampDisplay": "10-21-2026 08:03:20.000",
            "severity": "Error",
            "thread": 220,
            "format": "Ccm",
            "filePath": "CAS.log",
            "timezoneOffset": -300,
        },
        {
            "id": 1,
            "lineNumber": 2,
            "message": "Install completed",
            "component": None,
            "timestamp": None,
            "severity": "Success",
            "format": "Ccm",
            "filePath": "CAS.log",
            "timezoneOffset": None,
        },
    ],
    "formatDetected": "Ccm",
    "totalLines": 2,
    "parseErrors": 1,
    "filePath": "CAS.log",
    "fileSize": 10,
    "byteOffset": 10,
}


def _fake_bridge(tmp_path: Path, payload: object, code: int = 0, stderr: str = "") -> Path:
    script = tmp_path / "fake-bridge"
    script.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"sys.stdout.write({json.dumps(json.dumps(payload))})\n"
        f"sys.stderr.write({stderr!r})\n"
        f"sys.exit({code})\n",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def test_convert_maps_severity_time_and_format():
    parsed = convert(SAMPLE, Path("CAS.log"))
    assert len(parsed.events) == 2
    first, second = parsed.events
    assert first.severity == "error"
    assert first.source_type == "cmtraceopen:ccm"
    assert first.component == "ContentAccess"
    assert first.line_number == 1
    assert first.timestamp is not None
    assert first.timestamp.astimezone(timezone.utc) == datetime(2026, 10, 21, 13, 3, 20, tzinfo=timezone.utc)
    assert first.timestamp.utcoffset().total_seconds() == -300 * 60
    assert second.severity == "info"
    assert second.timestamp is None
    assert second.component == ""
    assert parsed.warnings == ["CAS.log: cmtraceopen reported 1 unparsed line(s)"]


def test_convert_rejects_missing_entries():
    with pytest.raises(LogsieveError):
        convert({"formatDetected": "Ccm"}, Path("x.log"))


@pytest.mark.skipif(os.name == "nt", reason="stand-in bridge is a shebang script")
def test_parse_path_uses_bridge_from_env(tmp_path, monkeypatch):
    log = tmp_path / "CAS.log"
    log.write_text("anything", encoding="utf-8")
    monkeypatch.setenv(BRIDGE_ENV, str(_fake_bridge(tmp_path, SAMPLE)))
    parsed = parse_path(log, parser="cmtraceopen")
    assert [event.severity for event in parsed.events] == ["error", "info"]
    assert parsed.events[0].source_file == str(log)


@pytest.mark.skipif(os.name == "nt", reason="stand-in bridge is a shebang script")
def test_bridge_failure_is_reported(tmp_path):
    bridge = _fake_bridge(tmp_path, {}, code=1, stderr="cannot read file")
    with pytest.raises(LogsieveError, match="cannot read file"):
        parse_cmtraceopen(tmp_path / "missing.log", bridge=str(bridge))


@pytest.mark.skipif(os.name == "nt", reason="stand-in bridge is a shebang script")
def test_bridge_invalid_json_is_reported(tmp_path):
    script = tmp_path / "bad-bridge"
    script.write_text(f"#!{sys.executable}\nprint('not json')\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    with pytest.raises(LogsieveError, match="invalid JSON"):
        parse_cmtraceopen(tmp_path / "x.log", bridge=str(script))


def test_missing_bridge_fails_clearly(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(BRIDGE_ENV, str(tmp_path / "does-not-exist"))
    assert find_bridge() is None
    with pytest.raises(LogsieveError, match="contrib/cmtraceopen-bridge"):
        parse_cmtraceopen(DEMO_LOGS / "CAS.log")
    code = main(
        ["diagnose", str(DEMO_LOGS / "CAS.log"), "--parser", "cmtraceopen", "--output", str(tmp_path / "out")]
    )
    assert code == 1
    assert "logsieve-cmtraceopen" in capsys.readouterr().err


def test_auto_parser_does_not_use_bridge(tmp_path, monkeypatch):
    monkeypatch.setenv(BRIDGE_ENV, str(tmp_path / "does-not-exist"))
    parsed = parse_path(DEMO_LOGS / "CAS.log")
    assert parsed.events
    assert all(event.source_type == "cmtrace" for event in parsed.events)


@pytest.mark.skipif(find_bridge() is None, reason="real logsieve-cmtraceopen bridge not built")
def test_real_bridge_matches_builtin_parser_on_demo_logs():
    for name in ("CAS.log", "AppEnforce.log", "IntuneManagementExtension.log"):
        builtin = parse_path(DEMO_LOGS / name)
        engine = parse_path(DEMO_LOGS / name, parser="cmtraceopen")
        assert len(engine.events) == len(builtin.events), name
        for ours, theirs in zip(builtin.events, engine.events):
            assert theirs.severity == ours.severity, name
            assert theirs.message == ours.message, name
            assert theirs.component == ours.component, name
            assert theirs.timestamp == ours.timestamp, name


@pytest.mark.skipif(find_bridge() is None, reason="real logsieve-cmtraceopen bridge not built")
def test_real_bridge_reads_cbs_timestamps_and_components():
    fixture = Path(__file__).resolve().parent / "fixtures" / "CBS.log"
    builtin = parse_path(fixture)
    assert all(event.timestamp is None for event in builtin.events)
    engine = parse_path(fixture, parser="cmtraceopen")
    assert [event.severity for event in engine.events] == ["info", "error", "warning"]
    assert [event.component for event in engine.events] == ["CBS", "CBS", "CSI"]
    assert all(event.source_type == "cmtraceopen:timestamped" for event in engine.events)
    assert engine.events[1].timestamp == datetime(2026, 10, 21, 8, 3, 21, tzinfo=timezone.utc)
    assert "0x800f0831" in engine.events[1].message
