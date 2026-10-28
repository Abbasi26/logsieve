from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from pathlib import Path

from logsieve.models import LogEvent, ParseResult
from logsieve.parsers.event_xml import LEVELS

ALIASES = {
    "time": {"timecreated", "date and time", "datetime", "time", "date"},
    "level": {"level", "leveldisplayname", "severity"},
    "provider": {"provider", "providername", "source"},
    "event_id": {"eventid", "event id", "id"},
    "message": {"message", "description"},
    "computer": {"computer", "computername", "machine", "hostname"},
    "user": {"user", "username", "account"},
}
TIME_FORMATS = (
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
)


def _norm_header(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().casefold())


def looks_like_event_csv(text: str) -> bool:
    first = ""
    for line in text.splitlines():
        if line.strip():
            first = _norm_header(line)
            break
    return "message" in first and ("event id" in first or "eventid" in first)


def _parse_time(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    iso = value.replace("Z", "+00:00")
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)
    try:
        return datetime.fromisoformat(iso)
    except ValueError:
        pass
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def parse_event_csv(text: str, source: Path) -> ParseResult:
    result = ParseResult()
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        result.warnings.append(f"{source}: CSV has no header")
        return result
    columns: dict[str, str] = {}
    for field in reader.fieldnames:
        normalized = _norm_header(field)
        for key, names in ALIASES.items():
            if normalized in names and key not in columns:
                columns[key] = field
    if "message" not in columns:
        result.warnings.append(f"{source}: CSV has no message column")
        return result
    for row in reader:
        if None in row:
            result.warnings.append(
                f"{source}:{reader.line_num}: skipped CSV row with extra fields"
            )
            continue
        if not any((value or "").strip() for value in row.values()):
            continue
        level = (row.get(columns.get("level", ""), "") or "").strip()
        result.events.append(
            LogEvent(
                timestamp=_parse_time(row.get(columns.get("time", ""), "") or ""),
                severity=LEVELS.get(level.casefold(), "unknown" if not level else "info"),
                source_file=str(source),
                source_type="event_csv",
                component=(row.get(columns.get("provider", ""), "") or "").strip(),
                provider=(row.get(columns.get("provider", ""), "") or "").strip(),
                event_id=str(row.get(columns.get("event_id", ""), "") or "").strip(),
                host=(row.get(columns.get("computer", ""), "") or "").strip(),
                user=(row.get(columns.get("user", ""), "") or "").strip(),
                message=(row.get(columns["message"], "") or "").strip(),
            )
        )
    return result
# Skipped: broader CSV policy changes; tests could not run without writable temp storage.
# Risk: malformed records are omitted with a warning; automatic fallback remains unchanged.
