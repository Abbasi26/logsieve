from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from logsieve.models import LogEvent, ParseResult

RECORD_SPLIT = "<![LOG["
# Closer is "]LOG]!>" : bracket, LOG, bracket, bang, angle.
RECORD_END = "]LOG]!>"
TYPE_SEVERITY = {
    "0": "info",
    "1": "info",
    "2": "warning",
    "3": "error",
    "4": "debug",
}
ATTR_RE = re.compile(r'(\w+)="([^"]*)"')
TIME_RE = re.compile(r"(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?([+-]\d+)?")
DATE_RE = re.compile(r"(\d{1,2})-(\d{1,2})-(\d{4})")


def parse_cm_timestamp(time_s: str, date_s: str) -> datetime | None:
    """Parse a CMTrace time and date.

    The numeric offset on the time, when present, is minutes from UTC.
    ``+000`` is UTC. ``-300`` is five hours west of UTC.
    """
    date_match = DATE_RE.search(date_s or "")
    time_match = TIME_RE.search(time_s or "")
    if not date_match or not time_match:
        return None
    month, day, year = (int(part) for part in date_match.groups())
    hour = int(time_match.group(1))
    minute = int(time_match.group(2))
    second = int(time_match.group(3))
    fraction = time_match.group(4) or "0"
    micro = int((fraction + "000000")[:6])
    offset = time_match.group(5)
    tz = timezone.utc
    if offset is not None:
        tz = timezone(timedelta(minutes=int(offset)))
    try:
        return datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)
    except ValueError:
        return None


def parse_cmtrace(text: str, source: Path, source_type: str = "cmtrace") -> ParseResult:
    result = ParseResult()
    if RECORD_SPLIT not in text:
        result.warnings.append(f"{source}: no CMTrace records found")
        return result
    for chunk in text.split(RECORD_SPLIT)[1:]:
        if RECORD_END not in chunk:
            result.warnings.append(f"{source}: truncated CMTrace record ignored")
            continue
        message, rest = chunk.split(RECORD_END, 1)
        attrs = dict(ATTR_RE.findall(rest))
        severity = TYPE_SEVERITY.get(attrs.get("type", "").strip(), "unknown")
        context = attrs.get("context", "").strip()
        result.events.append(
            LogEvent(
                timestamp=parse_cm_timestamp(attrs.get("time", ""), attrs.get("date", "")),
                severity=severity,
                source_file=str(source),
                source_type=source_type,
                component=attrs.get("component", "").strip(),
                user=context,
                message=message.strip(),
            )
        )
    return result