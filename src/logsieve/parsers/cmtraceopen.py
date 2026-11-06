"""Optional backend: the CMTrace Open parser engine through a small Rust bridge.

CMTrace Open (https://github.com/adamgell/cmtraceopen, MIT, by Adam Gell) ships its
parser as the Rust crate ``cmtraceopen-parser``. It recognizes more Windows log
formats than logsieve does on its own, for example CBS, DISM, Panther, MSI, PSADT,
WiX Burn, ReportingEvents, IIS W3C, DHCP, and DNS debug logs.

logsieve stays pure Python. This backend is used only with ``--parser cmtraceopen``
and only when the bridge binary from ``contrib/cmtraceopen-bridge`` is installed.
The bridge reads one file and prints the engine's parse result as JSON. It makes no
network calls and writes nothing.

The binary is found through ``LOGSIEVE_CMTRACEOPEN`` (a path) or as
``logsieve-cmtraceopen`` on ``PATH``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from logsieve.errors import LogsieveError
from logsieve.models import LogEvent, ParseResult

BRIDGE_ENV = "LOGSIEVE_CMTRACEOPEN"
BRIDGE_NAME = "logsieve-cmtraceopen"
DEFAULT_TIMEOUT = 120

SEVERITY_MAP = {
    "error": "error",
    "warning": "warning",
    "info": "info",
    "success": "info",
}


def find_bridge() -> str | None:
    """Return the bridge path, or None when it is not installed."""
    configured = os.environ.get(BRIDGE_ENV, "").strip()
    if configured:
        return configured if Path(configured).is_file() else None
    return shutil.which(BRIDGE_NAME)


def _timestamp(entry: dict) -> datetime | None:
    millis = entry.get("timestamp")
    if not isinstance(millis, (int, float)) or isinstance(millis, bool):
        return None
    try:
        stamp = datetime.fromtimestamp(millis / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    offset = entry.get("timezoneOffset")
    if isinstance(offset, int) and not isinstance(offset, bool) and -1440 < offset < 1440:
        stamp = stamp.astimezone(timezone(timedelta(minutes=offset)))
    return stamp


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def convert(payload: dict, source: Path) -> ParseResult:
    """Map the bridge JSON (a cmtraceopen-parser ParseResult) to logsieve events."""
    result = ParseResult()
    detected = _text(payload.get("formatDetected")) or "unknown"
    source_type = f"cmtraceopen:{detected.lower()}"
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise LogsieveError(f"{source}: cmtraceopen bridge returned no entries list")
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        severity = SEVERITY_MAP.get(_text(entry.get("severity")).lower(), "unknown")
        line = entry.get("lineNumber")
        result.events.append(
            LogEvent(
                timestamp=_timestamp(entry),
                severity=severity,
                source_file=str(source),
                source_type=source_type,
                component=_text(entry.get("component")),
                message=_text(entry.get("message")),
                line_number=line if isinstance(line, int) and not isinstance(line, bool) else None,
            )
        )
    errors = payload.get("parseErrors")
    if isinstance(errors, int) and errors > 0:
        result.warnings.append(f"{source}: cmtraceopen reported {errors} unparsed line(s)")
    return result


def parse_cmtraceopen(path: Path, bridge: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> ParseResult:
    """Parse one file with the CMTrace Open engine through the bridge binary."""
    binary = bridge or find_bridge()
    if not binary:
        raise LogsieveError(
            f"--parser cmtraceopen needs the {BRIDGE_NAME} binary; build it from "
            f"contrib/cmtraceopen-bridge and put it on PATH or set {BRIDGE_ENV}"
        )
    try:
        completed = subprocess.run(
            [binary, str(path)],
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise LogsieveError(f"{path}: cmtraceopen bridge timed out after {timeout}s") from exc
    except OSError as exc:
        raise LogsieveError(f"{path}: cannot run cmtraceopen bridge: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip() or f"exit code {completed.returncode}"
        raise LogsieveError(f"{path}: cmtraceopen bridge failed: {detail}")
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LogsieveError(f"{path}: cmtraceopen bridge returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise LogsieveError(f"{path}: cmtraceopen bridge returned unexpected JSON")
    return convert(payload, path)
