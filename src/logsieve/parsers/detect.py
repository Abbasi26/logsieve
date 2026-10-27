from __future__ import annotations

from pathlib import Path

from logsieve.io_util import read_text
from logsieve.models import ParseResult
from logsieve.parsers.cmtrace import parse_cmtrace
from logsieve.parsers.event_csv import looks_like_event_csv, parse_event_csv
from logsieve.parsers.event_xml import parse_event_xml
from logsieve.parsers.evtx import parse_evtx
from logsieve.parsers.ime import looks_like_ime, parse_ime
from logsieve.parsers.journald import looks_like_journald, parse_journald
from logsieve.parsers.plain import parse_plain

SKIP_SUFFIXES = {
    ".key",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".zip",
    ".cab",
    ".msi",
    ".exe",
    ".dll",
    ".pyc",
}
SKIP_NAMES = {"logsieve-vault.json", "report.md", "report.html"}


def parse_path(path: Path, parser: str = "auto") -> ParseResult:
    parser = parser or "auto"
    if parser == "evtx" or (parser == "auto" and path.suffix.lower() == ".evtx"):
        return parse_evtx(path)
    text = read_text(path)
    if parser == "cmtrace":
        return parse_cmtrace(text, path, source_type="cmtrace")
    if parser == "ime":
        return parse_ime(text, path)
    if parser == "event-xml":
        return parse_event_xml(text, path)
    if parser == "event-csv":
        return parse_event_csv(text, path)
    if parser == "journald":
        return parse_journald(text, path)
    if parser == "plain":
        return parse_plain(text, path)
    if "<![LOG[" in text:
        if looks_like_ime(path, text):
            return parse_ime(text, path)
        return parse_cmtrace(text, path, source_type="cmtrace")
    sample = text[:8000]
    if "<Event" in sample or "<event" in sample:
        return parse_event_xml(text, path)
    if path.suffix.lower() == ".csv" or looks_like_event_csv(text):
        parsed = parse_event_csv(text, path)
        if parsed.events:
            return parsed
    if path.suffix.lower() in {".jsonl", ".ndjson"} or looks_like_journald(text):
        parsed = parse_journald(text, path)
        if parsed.events:
            return parsed
    return parse_plain(text, path)


def iter_input_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            children = [item for item in path.rglob("*") if item.is_file() and not item.name.startswith(".")]
            files.extend(sorted(children))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(path)
    selected = []
    for path in files:
        if path.name in SKIP_NAMES or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        if path.name.endswith(".json.key") or path.name.endswith(".vault.json.key"):
            continue
        selected.append(path)
    return selected