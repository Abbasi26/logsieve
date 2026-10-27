from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from logsieve.errors import LogsieveError
from logsieve.models import LogEvent

LIBRARY_DIR = Path(__file__).resolve().parent / "library"
SEVERITIES = {"critical", "error", "warning", "info", "debug"}
CONFIDENCE = {"high", "medium", "low"}


@dataclass
class Pattern:
    id: str
    title: str
    severity: str
    confidence: str
    uncertain: bool
    category: str
    symptom_of: list[str]
    area: str
    explanation: str
    fix_hints: list[str]
    sources: list[str]
    notes: str = ""
    constant: str = ""
    codes: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    event_ids: list[tuple[str, str]] = field(default_factory=list)
    self_test: str = ""
    self_test_provider: str = ""
    self_test_event_id: str = ""
    _code_res: list[re.Pattern] = field(default_factory=list, repr=False)
    _sig_res: list[re.Pattern] = field(default_factory=list, repr=False)

    @property
    def annotation(self) -> bool:
        """Generic wrappers should not be reported as a separate root cause."""
        if self.category == "generic":
            return True
        return bool(self.event_ids) and not self.codes and not self.signatures

    def matches(self, event: LogEvent, blob: str) -> bool:
        if any(pattern.search(blob) for pattern in self._code_res):
            return True
        if any(pattern.search(blob) for pattern in self._sig_res):
            return True
        if self.constant and re.search(rf"\b{re.escape(self.constant)}\b", blob, re.IGNORECASE):
            return True
        for provider, event_id in self.event_ids:
            if event.event_id.strip() == event_id and (
                not provider or event.provider.casefold() == provider.casefold()
            ):
                return True
        return False

    @property
    def code_label(self) -> str:
        if self.codes:
            return self.codes[0]
        if self.constant:
            return self.constant
        if self.event_ids:
            provider, event_id = self.event_ids[0]
            return f"event {event_id}" + (f" ({provider})" if provider else "")
        return "signature"


def _code_regexes(code: str) -> list[re.Pattern]:
    raw = code.strip()
    compiled: list[re.Pattern] = []
    if re.fullmatch(r"0x[0-9A-Fa-f]+", raw, re.IGNORECASE):
        body = raw[2:]
        compiled.append(re.compile(rf"(?i)(?<![0-9A-Fa-f])0x{re.escape(body)}(?![0-9A-Fa-f])"))
        value = int(raw, 16)
        if value >= 2**31:
            signed = value - 2**32
            compiled.append(re.compile(rf"(?<!\d){signed}(?!\d)"))
        if value > 65535:
            compiled.append(re.compile(rf"(?<!\d){value}(?!\d)"))
        return compiled
    if re.fullmatch(r"\d+", raw):
        return [re.compile(rf"(?<!\d){re.escape(raw)}(?!\d)")]
    return [re.compile(rf"(?i)\b{re.escape(raw)}\b")]


def _pattern_from_dict(data: dict, origin: str) -> Pattern:
    if not isinstance(data, dict):
        raise LogsieveError(f"{origin}: pattern entry is not a mapping")
    identifier = str(data.get("id") or "").strip()
    title = str(data.get("title") or "").strip()
    if not identifier or not title:
        raise LogsieveError(f"{origin}: a pattern needs id and title")
    severity = str(data.get("severity") or "error").strip().casefold()
    confidence = str(data.get("confidence") or "medium").strip().casefold()
    if severity not in SEVERITIES:
        raise LogsieveError(f"{origin}: {identifier} has unknown severity {severity}")
    if confidence not in CONFIDENCE:
        raise LogsieveError(f"{origin}: {identifier} has unknown confidence {confidence}")
    sources = [str(item).strip() for item in data.get("sources") or [] if str(item).strip()]
    if not sources:
        raise LogsieveError(f"{origin}: {identifier} needs at least one source URL")
    codes = [str(item).strip() for item in data.get("codes") or [] if str(item).strip()]
    signatures = [str(item) for item in data.get("signatures") or [] if str(item).strip()]
    event_ids: list[tuple[str, str]] = []
    for item in data.get("event_ids") or []:
        if not isinstance(item, dict):
            raise LogsieveError(f"{origin}: {identifier} has a bad event_ids entry")
        event_ids.append((str(item.get("provider") or "").strip(), str(item.get("id") or "").strip()))
    if not codes and not signatures and not event_ids and not data.get("constant"):
        raise LogsieveError(f"{origin}: {identifier} has nothing to match")
    pattern = Pattern(
        id=identifier,
        title=title,
        severity=severity,
        confidence=confidence,
        uncertain=bool(data.get("uncertain", False)),
        category=str(data.get("category") or "unknown").strip(),
        symptom_of=[str(item) for item in data.get("symptom_of") or []],
        area=str(data.get("area") or "").strip(),
        explanation=str(data.get("explanation") or "").strip(),
        fix_hints=[str(item).strip() for item in data.get("fix_hints") or [] if str(item).strip()],
        sources=sources,
        notes=str(data.get("notes") or "").strip(),
        constant=str(data.get("constant") or "").strip(),
        codes=codes,
        signatures=signatures,
        event_ids=event_ids,
        self_test=str(data.get("self_test") or "").strip(),
        self_test_provider=str(data.get("self_test_provider") or "").strip(),
        self_test_event_id=str(data.get("self_test_event_id") or "").strip(),
    )
    for code in codes:
        pattern._code_res.extend(_code_regexes(code))
    for signature in signatures:
        try:
            pattern._sig_res.append(re.compile(signature))
        except re.error as exc:
            raise LogsieveError(f"{origin}: {identifier} has a bad signature ({exc})") from exc
    return pattern


def load_pattern_file(path: Path) -> list[Pattern]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw is None:
        return []
    if isinstance(raw, dict):
        raw = raw.get("patterns", [])
    if not isinstance(raw, list):
        raise LogsieveError(f"{path}: expected a list of patterns")
    return [_pattern_from_dict(item, str(path)) for item in raw]


def load_patterns(*directories: Path) -> list[Pattern]:
    patterns: list[Pattern] = []
    seen: set[str] = set()
    for directory in directories:
        if not directory.exists():
            raise LogsieveError(f"pattern directory not found: {directory}")
        for path in sorted(directory.glob("*.yaml")):
            for pattern in load_pattern_file(path):
                if pattern.id in seen:
                    raise LogsieveError(f"duplicate pattern id {pattern.id} in {path}")
                seen.add(pattern.id)
                patterns.append(pattern)
    return patterns


def load_builtin() -> list[Pattern]:
    return load_patterns(LIBRARY_DIR)


@dataclass
class Hit:
    pattern: Pattern
    event_index: int


def match_events(events: list[LogEvent], patterns: list[Pattern]) -> list[Hit]:
    hits: list[Hit] = []
    for index, event in enumerate(events):
        blob = event.search_text()
        for pattern in patterns:
            if pattern.matches(event, blob):
                hits.append(Hit(pattern=pattern, event_index=index))
    return hits