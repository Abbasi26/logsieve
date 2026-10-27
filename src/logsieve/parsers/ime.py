"""Intune Management Extension logs.

IntuneManagementExtension.log and AgentExecutor.log are written in the CMTrace
record format. This module is the IME entry point: it uses that grammar and
labels the events as ``ime`` so a report can tell the two families apart.
"""

from __future__ import annotations

from pathlib import Path

from logsieve.models import ParseResult
from logsieve.parsers.cmtrace import parse_cmtrace

IME_FILENAMES = {
    "intunemanagementextension.log",
    "agentexecutor.log",
    "sensor.log",
    "healthscripts.log",
    "clienthealth.log",
}
IME_MARKERS = (
    "intunemanagementextension",
    "agentexecutor",
    "scriptrunner",
    "[win32app]",
)


def looks_like_ime(path: Path, text: str) -> bool:
    if path.name.lower() in IME_FILENAMES:
        return True
    sample = text[:8000].casefold()
    return any(marker in sample for marker in IME_MARKERS)


def parse_ime(text: str, source: Path) -> ParseResult:
    return parse_cmtrace(text, source, source_type="ime")