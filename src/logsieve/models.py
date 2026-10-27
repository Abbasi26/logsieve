from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


SEVERITIES = ("critical", "error", "warning", "info", "debug", "unknown")


@dataclass
class LogEvent:
    timestamp: datetime | None
    severity: str
    source_file: str
    source_type: str
    component: str = ""
    provider: str = ""
    event_id: str = ""
    host: str = ""
    user: str = ""
    message: str = ""
    line_number: int | None = None
    order: int = 0
    display_source: str = ""
    display_host: str = ""
    display_user: str = ""
    display_component: str = ""
    display_message: str = ""

    def search_text(self) -> str:
        parts = [self.message, self.provider, self.event_id, self.component, self.host, self.user]
        return "\n".join(part for part in parts if part)


@dataclass
class ParseResult:
    events: list[LogEvent] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)