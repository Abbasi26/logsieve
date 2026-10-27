from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from logsieve.models import LogEvent, ParseResult

LEVELS = {
    "0": "unknown",
    "1": "critical",
    "2": "error",
    "3": "warning",
    "4": "info",
    "5": "debug",
    "critical": "critical",
    "error": "error",
    "warning": "warning",
    "information": "info",
    "info": "info",
    "verbose": "debug",
}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_time(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    candidate = value.replace("Z", "+00:00")
    # Windows event XML uses 7 fractional digits. Python accepts up to 6.
    candidate = re.sub(r"(\.\d{6})\d+", r"\1", candidate)
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _child_text(parent: ET.Element, name: str) -> str:
    for child in list(parent):
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return ""


def _event_from_element(element: ET.Element, source: Path, source_type: str) -> LogEvent:
    system = None
    rendering = None
    event_data = None
    for child in list(element):
        name = _local(child.tag)
        if name == "System":
            system = child
        elif name == "RenderingInfo":
            rendering = child
        elif name in {"EventData", "UserData"}:
            event_data = child
    provider = ""
    event_id = ""
    level = ""
    computer = ""
    user = ""
    timestamp = None
    if system is not None:
        for child in list(system):
            name = _local(child.tag)
            if name == "Provider":
                provider = child.attrib.get("Name") or (child.text or "").strip()
            elif name == "EventID":
                event_id = (child.text or "").strip()
            elif name == "Level":
                level = (child.text or "").strip()
            elif name == "Computer":
                computer = (child.text or "").strip()
            elif name == "TimeCreated":
                timestamp = _parse_time(child.attrib.get("SystemTime") or (child.text or ""))
            elif name == "Security":
                user = child.attrib.get("UserID") or (child.text or "").strip()
            elif name in {"UserID", "User"} and not user:
                user = (child.text or "").strip()
    pieces: list[str] = []
    if rendering is not None:
        rendered = _child_text(rendering, "Message")
        if rendered:
            pieces.append(rendered)
    if event_data is not None:
        for node in event_data.iter():
            if node is event_data:
                continue
            text = (node.text or "").strip()
            if not text:
                continue
            label = node.attrib.get("Name") or _local(node.tag)
            rendered = f"{label}={text}" if label else text
            if rendered not in "\n".join(pieces):
                pieces.append(rendered)
    if not pieces:
        pieces.append(f"Event {event_id} from {provider}".strip())
    severity = LEVELS.get(level.strip().casefold(), "unknown")
    return LogEvent(
        timestamp=timestamp,
        severity=severity,
        source_file=str(source),
        source_type=source_type,
        component=provider,
        provider=provider,
        event_id=event_id,
        host=computer,
        user=user,
        message="\n".join(pieces),
    )


def _roots(text: str) -> list[ET.Element]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        return [ET.fromstring(stripped)]
    except ET.ParseError:
        wrapped = f"<Events>{stripped}</Events>"
        try:
            return [ET.fromstring(wrapped)]
        except ET.ParseError:
            events = re.findall(r"<Event\b.*?</Event>", stripped, flags=re.DOTALL | re.IGNORECASE)
            roots: list[ET.Element] = []
            for chunk in events:
                try:
                    roots.append(ET.fromstring(chunk))
                except ET.ParseError:
                    continue
            return roots


def parse_event_xml(text: str, source: Path, source_type: str = "event_xml") -> ParseResult:
    result = ParseResult()
    roots = _roots(text)
    if not roots:
        result.warnings.append(f"{source}: no Windows event XML found")
        return result
    found = False
    for root in roots:
        elements = [root] if _local(root.tag) == "Event" else []
        elements.extend(node for node in root.iter() if _local(node.tag) == "Event" and node is not root)
        for element in elements:
            result.events.append(_event_from_element(element, source, source_type))
            found = True
    if not found:
        result.warnings.append(f"{source}: event XML did not contain an Event element")
    return result