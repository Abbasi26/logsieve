from __future__ import annotations

from pathlib import Path

from Evtx.Evtx import Evtx

from logsieve.models import ParseResult
from logsieve.parsers.event_xml import parse_event_xml


def parse_evtx(path: Path) -> ParseResult:
    result = ParseResult()
    try:
        with Evtx(str(path)) as log:
            for record in log.records():
                try:
                    xml = record.xml()
                except Exception as exc:  # python-evtx raises several parser errors
                    result.warnings.append(f"{path}: skipped a record ({exc})")
                    continue
                parsed = parse_event_xml(xml, path, source_type="evtx")
                result.events.extend(parsed.events)
                result.warnings.extend(parsed.warnings)
    except Exception as exc:
        result.warnings.append(f"{path}: failed to read EVTX ({exc})")
    if not result.events and not result.warnings:
        result.warnings.append(f"{path}: EVTX file contained no readable records")
    return result