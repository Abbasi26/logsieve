from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from logsieve.models import LogEvent, ParseResult

ISO_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.*)$"
)
LEVEL_RE = re.compile(r"\b(CRITICAL|FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG)\b", re.IGNORECASE)
LEVEL_MAP = {
    "critical": "critical",
    "fatal": "critical",
    "error": "error",
    "warn": "warning",
    "warning": "warning",
    "info": "info",
    "debug": "debug",
}


def _parse_iso(value: str) -> datetime | None:
    candidate = value.strip().replace("Z", "+00:00").replace(" ", "T", 1)
    candidate = re.sub(r"(\.\d{6})\d+", r"\1", candidate)
    if re.fullmatch(r".*[+-]\d{4}", candidate):
        candidate = candidate[:-2] + ":" + candidate[-2:]
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def parse_plain(text: str, source: Path) -> ParseResult:
    result = ParseResult()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        timestamp = None
        body = line.strip()
        matched = ISO_RE.match(body)
        if matched:
            timestamp = _parse_iso(matched.group(1))
            body = matched.group(2).strip()
        level = LEVEL_RE.search(body)
        severity = LEVEL_MAP.get(level.group(1).casefold(), "info") if level else "info"
        result.events.append(
            LogEvent(
                timestamp=timestamp,
                severity=severity,
                source_file=str(source),
                source_type="plain",
                message=body,
                line_number=line_number,
            )
        )
    return result