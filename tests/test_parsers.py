from datetime import datetime, timedelta, timezone
from pathlib import Path

from Evtx.Evtx import Evtx

from logsieve.parsers import parse_path
from logsieve.parsers.cmtrace import parse_cm_timestamp, parse_cmtrace
from logsieve.parsers.synthetic_evtx import build_evtx


def test_cmtrace_multiline_severity_and_offsets():
    text = """<![LOG[first line
second line]LOG]!><time="08:00:00.000+000" date="10-21-2026" component="AppEnforce" context="NORTHWIND\\ada.example" type="3" thread="1" file="AppEnforce.log">
<![LOG[warning only]LOG]!><time="03:00:00.000-300" date="10-21-2026" component="CAS" context="" type="2" thread="2" file="CAS.log">
"""
    parsed = parse_cmtrace(text, Path("AppEnforce.log"))
    assert len(parsed.events) == 2
    error = parsed.events[0]
    assert error.severity == "error"
    assert "second line" in error.message
    assert error.user == "NORTHWIND\\ada.example"
    stamp = error.timestamp
    assert stamp is not None
    assert stamp.astimezone(timezone.utc) == datetime(2026, 10, 21, 8, 0, tzinfo=timezone.utc)
    warning = parsed.events[1]
    assert warning.severity == "warning"
    assert warning.timestamp is not None
    assert warning.timestamp.astimezone(timezone.utc) == datetime(2026, 10, 21, 8, 0, tzinfo=timezone.utc)
    assert parse_cm_timestamp("08:00:00.000-300", "10-21-2026").astimezone(timezone.utc).hour == 13


def test_ime_filename_and_utf16(tmp_path: Path):
    record = (
        '<![LOG[Win32 app failed 0x87D1041C]LOG]!>'
        '<time="08:04:10.000+000" date="10-21-2026" component="IntuneManagementExtension" context="" type="3" thread="4" file="IntuneManagementExtension.log">\n'
    )
    path = tmp_path / "IntuneManagementExtension.log"
    path.write_bytes(b"\xff\xfe" + record.encode("utf-16-le"))
    parsed = parse_path(path)
    assert len(parsed.events) == 1
    assert parsed.events[0].source_type == "ime"
    assert parsed.events[0].severity == "error"
    assert "0x87D1041C" in parsed.events[0].message

    bare = tmp_path / "AgentExecutor.log"
    bare.write_bytes(record.replace("IntuneManagementExtension", "AgentExecutor").encode("utf-16-le"))
    parsed = parse_path(bare)
    assert parsed.events[0].source_type == "ime"


def test_event_xml_shapes(tmp_path: Path):
    exported = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-WindowsUpdateClient" />
        <EventID>31</EventID>
        <Level>2</Level>
        <TimeCreated SystemTime="2026-10-21T08:02:40.0000000Z" />
        <Computer>laptop-07.northwind.example</Computer>
        <Security UserID="S-1-5-21-1000000001-1000000002-1000000003-1001" />
      </System>
      <EventData><Data Name="Update">0x8024401C</Data></EventData>
      <RenderingInfo><Message>scan failed 0x8024401C</Message></RenderingInfo>
    </Event>
    """
    synthetic = """<Event><System><Provider>Microsoft-Windows-WindowsUpdateClient</Provider>
      <EventID>20</EventID><Level>2</Level>
      <Computer>laptop-07.northwind.example</Computer>
      <TimeCreated>2026-10-21T08:02:11.0000000Z</TimeCreated>
      <UserID>S-1-5-21-1000000001-1000000002-1000000003-1001</UserID>
      </System><RenderingInfo><Message>Installation Failure: 0x8024402C.</Message></RenderingInfo></Event>"""
    path = tmp_path / "events.xml"
    path.write_text(exported + "\n" + synthetic, encoding="utf-8")
    parsed = parse_path(path)
    assert len(parsed.events) == 2
    assert parsed.events[0].provider == "Microsoft-Windows-WindowsUpdateClient"
    assert parsed.events[0].event_id == "31"
    assert parsed.events[0].severity == "error"
    assert parsed.events[0].user.startswith("S-1-5-21-")
    assert "0x8024401C" in parsed.events[0].message
    assert parsed.events[1].event_id == "20"
    assert "0x8024402C" in parsed.events[1].message
    assert parsed.events[0].timestamp == datetime(2026, 10, 21, 8, 2, 40, tzinfo=timezone.utc)


def test_event_csv_quoted_comma(tmp_path: Path):
    path = tmp_path / "events.csv"
    path.write_text(
        "Level,Date and Time,Source,Event ID,Message,Computer\n"
        'Error,10/21/2026 8:03:05 AM,Microsoft-Windows-WindowsUpdateClient,31,"failed 0x80072EE7, retry",laptop-07\n',
        encoding="utf-8",
    )
    parsed = parse_path(path)
    assert len(parsed.events) == 1
    event = parsed.events[0]
    assert event.severity == "error"
    assert "0x80072EE7, retry" in event.message
    assert event.timestamp == datetime(2026, 10, 21, 8, 3, 5)


def test_journald_and_plain(tmp_path: Path):
    journal = tmp_path / "collector.jsonl"
    journal.write_text(
        '{"MESSAGE":"lookup files.example: no such host","PRIORITY":"3",'
        '"__REALTIME_TIMESTAMP":"1792569700000000","_HOSTNAME":"laptop-07.northwind.example"}\n',
        encoding="utf-8",
    )
    parsed = parse_path(journal)
    assert parsed.events[0].source_type == "journald"
    assert parsed.events[0].severity == "error"
    assert parsed.events[0].timestamp == datetime(2026, 10, 21, 8, 1, 40, tzinfo=timezone.utc)
    assert parsed.events[0].host == "laptop-07.northwind.example"

    plain = tmp_path / "notes.log"
    plain.write_text(
        "2026-10-21T08:01:05Z ERROR Windows Update failed with error 0x8024402C\n"
        "no timestamp here\n",
        encoding="utf-8",
    )
    parsed = parse_path(plain)
    assert parsed.events[0].severity == "error"
    assert parsed.events[0].timestamp == datetime(2026, 10, 21, 8, 1, 5, tzinfo=timezone.utc)
    assert parsed.events[1].timestamp is None
    assert parsed.events[1].severity == "info"


def test_timeline_sort(tmp_path: Path):
    later = tmp_path / "later.log"
    earlier = tmp_path / "earlier.log"
    later.write_text("2026-10-21T09:00:00Z ERROR later\n", encoding="utf-8")
    earlier.write_text("2026-10-21T08:00:00 ERROR earlier\n", encoding="utf-8")
    from logsieve.pipeline import collect_events

    events, _warnings = collect_events([later, earlier], "plain")
    assert [event.message for event in events] == ["ERROR earlier", "ERROR later"]


def test_synthetic_evtx_roundtrip(tmp_path: Path):
    when = datetime(2026, 10, 21, 8, 2, 11, tzinfo=timezone.utc)
    blob = build_evtx(
        [
            {
                "provider": "Microsoft-Windows-WindowsUpdateClient",
                "event_id": "20",
                "level": "2",
                "computer": "laptop-07.northwind.example",
                "time": "2026-10-21T08:02:11.0000000Z",
                "when": when,
                "message": "Installation Failure: Windows failed to install the following update with error 0x8024402C.",
            },
            {
                "provider": "Application",
                "event_id": "1",
                "level": "4",
                "computer": "laptop-07.northwind.example",
                "time": "2026-10-21T08:02:12.0000000Z",
                "when": when + timedelta(seconds=1),
                "message": "second fictional record",
            },
        ]
    )
    path = tmp_path / "WindowsUpdate.evtx"
    path.write_bytes(blob)
    with Evtx(str(path)) as log:
        assert log.get_file_header().verify()
        chunks = list(log.chunks())
        assert len(chunks) == 1
        assert chunks[0].verify()
        records = list(log.records())
        assert len(records) == 2
        assert "0x8024402C" in records[0].xml()
    parsed = parse_path(path)
    assert len(parsed.events) == 2
    assert parsed.events[0].source_type == "evtx"
    assert parsed.events[0].event_id == "20"
    assert "0x8024402C" in parsed.events[0].message
    assert parsed.events[0].host == "laptop-07.northwind.example"


import json

import pytest


@pytest.mark.parametrize("parser", ["auto", "journald"])
def test_journald_zero_timestamp_and_fallbacks(tmp_path: Path, parser: str):
    path = tmp_path / "collector.jsonl"
    primary_fields = [
        {"__REALTIME_TIMESTAMP": 0},
        {"__REALTIME_TIMESTAMP": "0"},
        {},
        {"__REALTIME_TIMESTAMP": None},
        {"__REALTIME_TIMESTAMP": ""},
        {"__REALTIME_TIMESTAMP": "invalid"},
    ]
    path.write_text(
        "\n".join(
            json.dumps({
                "MESSAGE": "timestamp regression",
                "_SOURCE_REALTIME_TIMESTAMP": "1000000",
                "timestamp": "2026-10-21T08:00:00Z",
                **fields,
            })
            for fields in primary_fields
        ),
        encoding="utf-8",
    )

    parsed = parse_path(path, parser)

    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    source = epoch + timedelta(seconds=1)
    iso = datetime(2026, 10, 21, 8, tzinfo=timezone.utc)
    assert [event.timestamp for event in parsed.events] == [
        epoch, epoch, source, source, source, iso,
    ]
    assert parsed.warnings == []
