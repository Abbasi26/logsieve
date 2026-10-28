"""Offline lookup of an error code, constant, pattern id, or log line in the pattern library."""

from __future__ import annotations

import re
from dataclasses import dataclass

from logsieve.models import LogEvent
from logsieve.patterns.matcher import Pattern

FACILITY_NAMES = {
    0: "null",
    4: "ITF",
    7: "Win32",
    8: "Windows",
    36: "Windows Update",
}


@dataclass
class CodeForms:
    hex: str
    unsigned: int
    signed: int
    facility: int | None
    facility_name: str
    code: int | None

    def as_dict(self) -> dict:
        return {
            "hex": self.hex,
            "unsigned": self.unsigned,
            "signed": self.signed,
            "facility": self.facility,
            "facility_name": self.facility_name,
            "code": self.code,
        }


@dataclass
class Explanation:
    query: str
    forms: CodeForms | None
    matches: list[tuple[Pattern, str]]

    def as_dict(self) -> dict:
        return {
            "query": self.query,
            "forms": self.forms.as_dict() if self.forms else None,
            "matches": [
                {
                    "id": pattern.id,
                    "title": pattern.title,
                    "match": pattern.code_label,
                    "via": via,
                    "area": pattern.area,
                    "category": pattern.category,
                    "confidence": pattern.confidence,
                    "uncertain": pattern.uncertain,
                    "symptom_of": list(pattern.symptom_of),
                    "explanation": pattern.explanation,
                    "notes": pattern.notes,
                    "checks": list(pattern.fix_hints),
                    "sources": list(pattern.sources),
                }
                for pattern, via in self.matches
            ],
        }


def code_forms(query: str) -> CodeForms | None:
    """Read a query as a 32-bit code: 0x8024402C, 8024402C, -2145107924, or 2149859372."""
    raw = query.strip()
    value: int | None = None
    if re.fullmatch(r"0x[0-9A-Fa-f]{1,8}", raw):
        value = int(raw, 16)
    elif re.fullmatch(r"[0-9A-Fa-f]{8}", raw) and re.search(r"[A-Fa-f]", raw):
        value = int(raw, 16)
    elif re.fullmatch(r"-\d{1,10}", raw):
        number = int(raw)
        if -(2**31) <= number < 0:
            value = number + 2**32
    elif re.fullmatch(r"\d{1,10}", raw):
        number = int(raw)
        if number < 2**32:
            value = number
    if value is None:
        return None
    signed = value - 2**32 if value >= 2**31 else value
    facility: int | None = None
    code: int | None = None
    name = ""
    if value >= 2**31:
        facility = (value >> 16) & 0x7FF
        code = value & 0xFFFF
        name = FACILITY_NAMES.get(facility, "")
    return CodeForms(
        hex=f"0x{value:08X}",
        unsigned=value,
        signed=signed,
        facility=facility,
        facility_name=name,
        code=code,
    )


def _probe(text: str) -> LogEvent:
    return LogEvent(timestamp=None, severity="error", source_file="query", source_type="plain", message=text)


def _match_text(text: str, patterns: list[Pattern]) -> list[Pattern]:
    event = _probe(text)
    blob = event.search_text()
    return [pattern for pattern in patterns if pattern.matches(event, blob)]


def explain(query: str, patterns: list[Pattern]) -> Explanation:
    text = query.strip()
    forms = code_forms(text)
    found: list[tuple[Pattern, str]] = []
    seen: set[str] = set()

    def add(items: list[Pattern], via: str) -> None:
        for pattern in items:
            if pattern.id not in seen:
                seen.add(pattern.id)
                found.append((pattern, via))

    by_id = [pattern for pattern in patterns if pattern.id.casefold() == text.casefold()]
    add(by_id, "pattern id")
    probes = [text]
    if forms is not None:
        probes.append(forms.hex)
    for probe in probes:
        add(_match_text(probe, patterns), "code or text")
    for pattern in patterns:
        for provider, event_id in pattern.event_ids:
            if text == event_id or text.casefold() == f"event {event_id}".casefold():
                add([pattern], f"event id {event_id}" + (f" ({provider})" if provider else ""))
    if forms is not None and forms.facility == 7 and forms.code is not None:
        add(_match_text(str(forms.code), patterns), f"Win32 code {forms.code}")
    return Explanation(query=text, forms=forms, matches=found)


def render_text(result: Explanation) -> str:
    lines: list[str] = []
    forms = result.forms
    if forms is not None:
        line = f"{result.query}: {forms.hex}  unsigned {forms.unsigned}  signed {forms.signed}"
        if forms.facility is not None:
            label = f" ({forms.facility_name})" if forms.facility_name else ""
            line += f"  facility {forms.facility}{label}  code {forms.code}"
        lines.append(line)
    if not result.matches:
        lines.append(f"No pattern in the library matches {result.query!r}.")
        lines.append("A miss means the code is not in the library. It says nothing about the log.")
        return "\n".join(lines) + "\n"
    for pattern, via in result.matches:
        flag = "  UNCERTAIN" if pattern.uncertain else ""
        if lines:
            lines.append("")
        lines.append(f"{pattern.title}")
        lines.append(f"  id: {pattern.id}  match: {pattern.code_label}  via: {via}")
        lines.append(f"  area: {pattern.area or '-'}  category: {pattern.category}  confidence: {pattern.confidence}{flag}")
        if pattern.symptom_of:
            lines.append(f"  can be a symptom of: {', '.join(pattern.symptom_of)}")
        if pattern.explanation:
            lines.append("")
            lines.extend(f"  {part}" for part in _wrap(pattern.explanation))
        if pattern.notes:
            lines.extend(f"  {part}" for part in _wrap(pattern.notes))
        if pattern.fix_hints:
            lines.append("  checks:")
            lines.extend(f"    - {hint}" for hint in pattern.fix_hints)
        lines.append("  sources:")
        lines.extend(f"    - {source}" for source in pattern.sources)
    return "\n".join(lines) + "\n"


def _wrap(text: str, width: int = 88) -> list[str]:
    import textwrap

    return textwrap.wrap(" ".join(text.split()), width=width) or [""]
