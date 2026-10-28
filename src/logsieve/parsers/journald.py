from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from logsieve.models import LogEvent, ParseResult

PRIORITY = {
    "0": "critical",
    "1": "critical",
    "2": "critical",
    "3": "error",
    "4": "warning",
    "5": "info",
    "6": "info",
    "7": "debug",
}


def looks_like_journald(text: str) -> bool:
    seen = 0
    hits = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        seen += 1
        if seen > 20:
            break
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "MESSAGE" in obj:
            hits += 1
    return hits > 0 and hits * 2 >= max(seen, 1)


def _timestamp(obj: dict) -> datetime | None:
    raw = obj.get("__REALTIME_TIMESTAMP")
    if raw in (None, ""):
        raw = obj.get("_SOURCE_REALTIME_TIMESTAMP")
    if raw not in (None, ""):
        try:
            return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                microseconds=int(str(raw))
            )
        except (ValueError, OSError, OverflowError):
            pass
    iso = obj.get("timestamp") or obj.get("__TIMESTAMP")
    if isinstance(iso, str) and iso.strip():
        candidate = iso.strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            return None
    return None


def parse_journald(text: str, source: Path) -> ParseResult:
    result = ParseResult()
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            result.warnings.append(f"{source}:{line_number}: skipped a line that is not JSON")
            continue
        if not isinstance(obj, dict) or "MESSAGE" not in obj:
            result.warnings.append(f"{source}:{line_number}: JSON object has no MESSAGE")
            continue
        priority = str(obj.get("PRIORITY", "")).strip()
        component = str(obj.get("SYSLOG_IDENTIFIER") or obj.get("_COMM") or obj.get("UNIT") or "")
        result.events.append(
            LogEvent(
                timestamp=_timestamp(obj),
                severity=PRIORITY.get(priority, "info"),
                source_file=str(source),
                source_type="journald",
                component=component,
                provider=component,
                host=str(obj.get("_HOSTNAME") or ""),
                message=str(obj.get("MESSAGE") or ""),
                line_number=line_number,
            )
        )
    return result

