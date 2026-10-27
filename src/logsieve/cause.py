"""Rank pattern hits into one suspected cause.

A specific code that can explain other hits outranks a generic code and an
event id. name-resolution, proxy, and timeout also satisfy a symptom listed
as "network". That link is a hint from the library, not proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from logsieve.models import LogEvent
from logsieve.patterns.matcher import Hit, Pattern

SEV = {"critical": 5, "error": 4, "warning": 2, "info": 1, "debug": 1, "unknown": 1}
CONF = {"high": 3, "medium": 2, "low": 1}


def format_timestamp(value: datetime | None) -> str:
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def category_satisfies(category: str, wanted: str) -> bool:
    if category == wanted:
        return True
    if wanted == "network" and category in {"name-resolution", "proxy", "timeout"}:
        return True
    return False


def _score(pattern: Pattern, count: int) -> float:
    value = float(SEV.get(pattern.severity, 1) * CONF.get(pattern.confidence, 1))
    if pattern.uncertain:
        value *= 0.5
    value += min(count, 5) * 0.2
    return value


@dataclass
class Finding:
    pattern: Pattern
    count: int
    score: float
    first_order: int
    samples: list[str] = field(default_factory=list)


@dataclass
class Diagnosis:
    primary: Finding | None
    confidence: str
    narrative: str
    supporting: list[Finding]
    explained: list[Finding]
    independent: list[Finding]
    annotations: list[Finding]
    steps: list[str]
    findings: list[Finding]


def _sample(event: LogEvent) -> str:
    message = (event.display_message or "").replace("\n", " ").strip()
    if len(message) > 240:
        message = message[:237] + "..."
    name = (event.display_source or event.source_file or "").replace("\\", "/").rsplit("/", 1)[-1]
    user = (event.display_user or "").strip()
    user_bit = f" user={user}" if user else ""
    stamp = format_timestamp(event.timestamp)
    prefix = f"{stamp} " if stamp else ""
    return f"{prefix}{event.severity} {name}{user_bit} {message}".strip()


def _better(left: Finding, right: Finding) -> bool:
    if left.score != right.score:
        return left.score > right.score
    if left.first_order != right.first_order:
        return left.first_order < right.first_order
    return left.pattern.id < right.pattern.id


def _best(findings: list[Finding]) -> Finding | None:
    chosen: Finding | None = None
    for finding in findings:
        if chosen is None or _better(finding, chosen):
            chosen = finding
    return chosen


def _explains(cause: Finding, other: Finding) -> bool:
    return any(category_satisfies(cause.pattern.category, wanted) for wanted in other.pattern.symptom_of)


def _corroborated(primary: Finding, findings: list[Finding]) -> bool:
    if primary.count >= 2:
        return True
    for other in findings:
        if other.pattern.id == primary.pattern.id or other.pattern.annotation:
            continue
        if other.pattern.category == primary.pattern.category or _explains(primary, other):
            return True
    return False


def build_diagnosis(events: list[LogEvent], hits: list[Hit]) -> Diagnosis:
    grouped: dict[str, list[int]] = {}
    patterns: dict[str, Pattern] = {}
    for hit in hits:
        grouped.setdefault(hit.pattern.id, []).append(hit.event_index)
        patterns[hit.pattern.id] = hit.pattern
    findings: list[Finding] = []
    for identifier, indexes in grouped.items():
        pattern = patterns[identifier]
        unique = list(dict.fromkeys(indexes))
        samples = [_sample(events[index]) for index in unique[:3]]
        findings.append(
            Finding(
                pattern=pattern,
                count=len(unique),
                score=_score(pattern, len(unique)),
                # Index in the time-sorted event list, so equal scores keep the earlier event.
                first_order=min(unique) if unique else 0,
                samples=samples,
            )
        )
    findings.sort(key=lambda item: (-item.score, item.first_order, item.pattern.id))
    specific = [item for item in findings if not item.pattern.annotation]
    candidates = [
        item
        for item in specific
        if any(_explains(item, other) for other in findings if other.pattern.id != item.pattern.id)
    ]
    primary = _best(candidates) or _best(specific) or _best(findings)
    supporting: list[Finding] = []
    explained: list[Finding] = []
    independent: list[Finding] = []
    annotations: list[Finding] = []
    if primary is not None:
        for item in findings:
            if item.pattern.id == primary.pattern.id:
                continue
            if item.pattern.annotation:
                annotations.append(item)
            elif item.pattern.category == primary.pattern.category:
                supporting.append(item)
            elif _explains(primary, item):
                explained.append(item)
            else:
                independent.append(item)
    else:
        annotations = [item for item in findings if item.pattern.annotation]
    if primary is None:
        confidence = "none"
        narrative = "No pattern in the library matched these events."
    else:
        if primary.pattern.uncertain or primary.pattern.confidence == "low":
            confidence = "low"
        elif primary.pattern.confidence == "high" and _corroborated(primary, findings):
            confidence = "high"
        else:
            confidence = "medium"
        narrative = primary.pattern.explanation.strip()
        if primary.pattern.uncertain:
            narrative += " This pattern is marked uncertain."
        if explained:
            narrative += (
                " Other matched codes are listed as possible symptoms of this category."
                " That link is a hint from the pattern library, not proof that one event caused the others."
            )
    steps: list[str] = []
    if primary is not None:
        steps.extend(primary.pattern.fix_hints)
    for item in independent:
        if item.pattern.fix_hints:
            steps.append(item.pattern.fix_hints[0])
    steps.append("These are checks to run. logsieve does not change the device.")
    return Diagnosis(
        primary=primary,
        confidence=confidence,
        narrative=narrative,
        supporting=supporting,
        explained=explained,
        independent=independent,
        annotations=annotations,
        steps=steps,
        findings=findings,
    )