"""Markdown and self-contained HTML reports. Both are built from redacted fields."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from logsieve.cause import Diagnosis, Finding, format_timestamp
from logsieve.models import LogEvent
from logsieve.pseudo.engine import RedactOptions

LIMITATIONS = (
    "Redaction is heuristic. A bare account name is removed when it appears in a user field, a user-profile path, an email, a DOMAIN\\user pair, or --username. A name that never appears in one of those shapes can remain.",
    "GUIDs are masked by default. Some of them are object ids in an error text rather than a device id. --keep-guids leaves them visible.",
    "IPv4 and IPv6 addresses are masked by default. A dotted build number such as 10.0.22621.3527 is left as-is because an octet does not fit in an IPv4 address. A value such as 1.2.3.4 is masked.",
    "The pattern library is a curated subset of published MECM, Intune, Windows Update, and Win32 codes. A code that does not match is missing from this library, which is not the same as a clean log.",
    "The suspected cause is a ranking hint. It is not a proof, and logsieve does not change the endpoint.",
    "Assignments that look like a password or an API key are masked on a best-effort basis. A secret in another shape can remain.",
)


@dataclass
class Report:
    generated: datetime
    inputs: list[str]
    event_count: int
    error_count: int
    redaction_note: str
    vault_note: str
    llm_note: str
    diagnosis: Diagnosis
    events: list[LogEvent]
    warnings: list[str]
    llm_answer: str | None = None


def redaction_note(options: RedactOptions) -> str:
    if not options.enabled:
        return "off. Identifiers in this report are unchanged."
    masked = ["hostnames", "accounts and email", "SIDs", "domain names", "user-profile paths"]
    if options.ips:
        masked.append("IPv4 and IPv6")
    else:
        masked.append("IP addresses kept (--keep-ips)")
    if options.guids:
        masked.append("GUIDs")
    else:
        masked.append("GUIDs kept (--keep-guids)")
    return "on (" + ", ".join(masked) + "). Tokens such as LS_HOST_1 stay stable for this run."


def _basename(event: LogEvent) -> str:
    raw = event.display_source or event.source_file or ""
    return raw.replace("\\", "/").rsplit("/", 1)[-1]


def _md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def _finding_line(finding: Finding) -> str:
    flag = " uncertain" if finding.pattern.uncertain else ""
    return f"{finding.pattern.title} (`{finding.pattern.id}`, {finding.pattern.code_label}, {finding.pattern.confidence}{flag}, {finding.count} event{'s' if finding.count != 1 else ''})"


def _pattern_block_md(finding: Finding) -> list[str]:
    pattern = finding.pattern
    flag = " yes" if pattern.uncertain else " no"
    lines = [
        f"### {pattern.title}",
        "",
        f"- id: `{pattern.id}`",
        f"- match: {pattern.code_label}",
        f"- confidence: {pattern.confidence}",
        f"- uncertain:{flag}",
        f"- category: {pattern.category}",
        f"- events: {finding.count}",
        "",
        pattern.explanation.strip(),
        "",
    ]
    if pattern.notes:
        lines.extend([pattern.notes.strip(), ""])
    if finding.samples:
        lines.append("Samples:")
        lines.append("")
        lines.extend(f"- {sample}" for sample in finding.samples)
        lines.append("")
    if pattern.fix_hints:
        lines.append("Checks:")
        lines.append("")
        lines.extend(f"- {hint}" for hint in pattern.fix_hints)
        lines.append("")
    if pattern.sources:
        lines.append("Sources:")
        lines.append("")
        lines.extend(f"- {source}" for source in pattern.sources)
        lines.append("")
    return lines


def render_markdown(report: Report) -> str:
    diagnosis = report.diagnosis
    lines = [
        "# logsieve diagnosis",
        "",
        f"Generated: {format_timestamp(report.generated)}",
        f"Events: {report.event_count} ({report.error_count} error or critical)",
        "Inputs:",
        "",
    ]
    if report.inputs:
        lines.extend(f"- {item}" for item in report.inputs)
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            f"Redaction: {report.redaction_note}",
            f"Vault: {report.vault_note}",
            f"LLM: {report.llm_note}",
            "",
            "## Suspected root cause",
            "",
        ]
    )
    if diagnosis.primary is None:
        lines.append(diagnosis.narrative)
    else:
        primary = diagnosis.primary
        lines.append(f"**{_finding_line(primary)}**")
        lines.append("")
        lines.append(f"Confidence in this ranking: {diagnosis.confidence}.")
        lines.append("")
        lines.append(diagnosis.narrative)
        if diagnosis.supporting:
            lines.extend(["", "Same category, also matched:", ""])
            lines.extend(f"- {_finding_line(item)}" for item in diagnosis.supporting)
    lines.extend(["", "## Next steps", ""])
    lines.extend(f"- {step}" for step in diagnosis.steps)
    if diagnosis.explained:
        lines.extend(["", "## Consistent with that cause", ""])
        lines.append(
            "These codes are listed as possible symptoms. The listing is a hint, not proof."
        )
        lines.append("")
        lines.extend(f"- {_finding_line(item)}" for item in diagnosis.explained)
    if diagnosis.independent:
        lines.extend(["", "## Separate findings", ""])
        lines.append("These matches are not explained by the suspected cause.")
        lines.append("")
        lines.extend(f"- {_finding_line(item)}" for item in diagnosis.independent)
    if diagnosis.annotations:
        lines.extend(["", "## Notes that are not the cause", ""])
        lines.append(
            "These matched an event id or a generic code. They stay in the report as notes."
        )
        lines.append("")
        lines.extend(f"- {_finding_line(item)}" for item in diagnosis.annotations)
    lines.extend(["", "## Matched patterns", ""])
    if not diagnosis.findings:
        lines.append("No library pattern matched.")
    else:
        for finding in diagnosis.findings:
            lines.extend(_pattern_block_md(finding))
    lines.extend(["## Error timeline", ""])
    errors = [event for event in report.events if event.severity in {"error", "critical"}]
    shown = errors[:200]
    if not shown:
        lines.append("No error or critical events.")
    else:
        lines.append("| Time (UTC) | Severity | Source | User | Message |")
        lines.append("| --- | --- | --- | --- | --- |")
        for event in shown:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md_cell(format_timestamp(event.timestamp)),
                        _md_cell(event.severity),
                        _md_cell(_basename(event)),
                        _md_cell(event.display_user or ""),
                        _md_cell(event.display_message or ""),
                    ]
                )
                + " |"
            )
        if len(errors) > len(shown):
            lines.append("")
            lines.append(f"Timeline truncated to {len(shown)} of {len(errors)} error events.")
    lines.extend(["", "## Warnings", ""])
    if report.warnings:
        lines.extend(f"- {warning}" for warning in report.warnings)
    else:
        lines.append("None.")
    if report.llm_answer:
        lines.extend(["", "## Model note", "", report.llm_answer.strip(), ""])
        lines.append("The model saw only the redacted diagnosis. Check it against the pattern sources above.")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in LIMITATIONS)
    lines.append("")
    return "\n".join(lines)


def _p(text: str) -> str:
    return f"<p>{html.escape(text)}</p>"


def _finding_html(finding: Finding) -> str:
    pattern = finding.pattern
    flag = " · uncertain" if pattern.uncertain else ""
    title = html.escape(pattern.title)
    ident = html.escape(pattern.id)
    code = html.escape(pattern.code_label)
    meta = html.escape(f"{pattern.confidence}{flag} · {finding.count} event" + ("s" if finding.count != 1 else ""))
    return f"<li><strong>{title}</strong> <code>{ident}</code> · {code} · {meta}</li>"


def _pattern_html(finding: Finding) -> str:
    pattern = finding.pattern
    parts = [
        "<section class=\"pattern\">",
        f"<h3>{html.escape(pattern.title)}</h3>",
        "<ul>",
        f"<li>id <code>{html.escape(pattern.id)}</code></li>",
        f"<li>match {html.escape(pattern.code_label)}</li>",
        f"<li>confidence {html.escape(pattern.confidence)}</li>",
        f"<li>uncertain {'yes' if pattern.uncertain else 'no'}</li>",
        f"<li>category {html.escape(pattern.category)}</li>",
        f"<li>events {finding.count}</li>",
        "</ul>",
        _p(pattern.explanation.strip()),
    ]
    if pattern.notes:
        parts.append(_p(pattern.notes.strip()))
    if finding.samples:
        parts.append("<p>Samples</p><ul>")
        parts.extend(f"<li><code>{html.escape(sample)}</code></li>" for sample in finding.samples)
        parts.append("</ul>")
    if pattern.fix_hints:
        parts.append("<p>Checks</p><ul>")
        parts.extend(f"<li>{html.escape(hint)}</li>" for hint in pattern.fix_hints)
        parts.append("</ul>")
    if pattern.sources:
        parts.append("<p>Sources</p><ul>")
        for source in pattern.sources:
            safe = html.escape(source, quote=True)
            if source.startswith("https://"):
                parts.append(f"<li><a href=\"{safe}\">{html.escape(source)}</a></li>")
            else:
                parts.append(f"<li>{html.escape(source)}</li>")
        parts.append("</ul>")
    parts.append("</section>")
    return "\n".join(parts)


def render_html(report: Report) -> str:
    diagnosis = report.diagnosis
    inputs = "".join(f"<li>{html.escape(item)}</li>" for item in report.inputs) or "<li>none</li>"
    if diagnosis.primary is None:
        cause = _p(diagnosis.narrative)
    else:
        cause = (
            "<ul>"
            + _finding_html(diagnosis.primary)
            + "</ul>"
            + _p(f"Confidence in this ranking: {diagnosis.confidence}.")
            + _p(diagnosis.narrative)
        )
        if diagnosis.supporting:
            cause += "<p>Same category, also matched</p><ul>"
            cause += "".join(_finding_html(item) for item in diagnosis.supporting)
            cause += "</ul>"
    steps = "".join(f"<li>{html.escape(step)}</li>" for step in diagnosis.steps)
    explained = ""
    if diagnosis.explained:
        explained = (
            "<h2>Consistent with that cause</h2>"
            + _p("These codes are listed as possible symptoms. The listing is a hint, not proof.")
            + "<ul>"
            + "".join(_finding_html(item) for item in diagnosis.explained)
            + "</ul>"
        )
    separate = ""
    if diagnosis.independent:
        separate = (
            "<h2>Separate findings</h2>"
            + _p("These matches are not explained by the suspected cause.")
            + "<ul>"
            + "".join(_finding_html(item) for item in diagnosis.independent)
            + "</ul>"
        )
    notes = ""
    if diagnosis.annotations:
        notes = (
            "<h2>Notes that are not the cause</h2>"
            + _p("These matched an event id or a generic code. They stay in the report as notes.")
            + "<ul>"
            + "".join(_finding_html(item) for item in diagnosis.annotations)
            + "</ul>"
        )
    if diagnosis.findings:
        patterns = "\n".join(_pattern_html(item) for item in diagnosis.findings)
    else:
        patterns = _p("No library pattern matched.")
    errors = [event for event in report.events if event.severity in {"error", "critical"}][:200]
    if errors:
        rows = []
        for event in errors:
            kind = "critical" if event.severity == "critical" else "error"
            rows.append(
                "<tr>"
                f"<td>{html.escape(format_timestamp(event.timestamp))}</td>"
                f"<td class=\"{kind}\">{html.escape(event.severity)}</td>"
                f"<td>{html.escape(_basename(event))}</td>"
                f"<td>{html.escape(event.display_user or '')}</td>"
                f"<td>{html.escape(event.display_message or '')}</td>"
                "</tr>"
            )
        extra = ""
        total = sum(1 for event in report.events if event.severity in {"error", "critical"})
        if total > len(errors):
            extra = _p(f"Timeline truncated to {len(errors)} of {total} error events.")
        timeline = (
            "<div class=\"timeline\"><table><thead><tr>"
            "<th>Time (UTC)</th><th>Severity</th><th>Source</th><th>User</th><th>Message</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></div>"
            + extra
        )
    else:
        timeline = _p("No error or critical events.")
    if report.warnings:
        warnings = "<ul>" + "".join(f"<li>{html.escape(item)}</li>" for item in report.warnings) + "</ul>"
    else:
        warnings = _p("None.")
    model = ""
    if report.llm_answer:
        model = (
            "<h2>Model note</h2>"
            + "".join(_p(part) for part in report.llm_answer.strip().split("\n\n"))
            + _p("The model saw only the redacted diagnosis. Check it against the pattern sources above.")
        )
    limits = "<ul>" + "".join(f"<li>{html.escape(item)}</li>" for item in LIMITATIONS) + "</ul>"
    generated = html.escape(format_timestamp(report.generated))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>logsieve diagnosis</title>
<style>
:root {{
  --paper: #f6f3ec;
  --ink: #1e1a16;
  --brick: #8f2d2d;
  --rule: #d9d1c3;
  --muted: #5c534a;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font-family: "Segoe UI", "Source Sans 3", "Noto Sans", sans-serif;
  line-height: 1.5;
}}
main {{
  max-width: 920px;
  margin: 0 auto;
  padding: 1.5rem 1.25rem 3rem;
}}
h1 {{
  font-size: 1.8rem;
  font-weight: 600;
  letter-spacing: -0.02em;
  margin-bottom: 0.25rem;
}}
h2 {{
  font-size: 1.15rem;
  margin-top: 2rem;
  border-top: 1px solid var(--rule);
  padding-top: 1rem;
}}
h3 {{ font-size: 1rem; margin-bottom: 0.25rem; }}
p, li {{ font-size: 0.98rem; }}
.meta {{ color: var(--muted); font-size: 0.92rem; }}
code {{
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace;
  font-size: 0.88em;
}}
a {{ color: var(--brick); }}
.error, .critical {{ color: var(--brick); font-weight: 600; }}
.timeline {{ overflow-x: auto; }}
table {{
  width: 100%;
  min-width: 640px;
  border-collapse: collapse;
  font-size: 0.9rem;
}}
th, td {{
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--rule);
  padding: 0.4rem 0.5rem;
}}
.pattern {{
  border-top: 1px solid var(--rule);
  padding-top: 0.5rem;
  margin-top: 1rem;
}}
@media print {{
  body {{ background: #fff; }}
  .timeline {{ overflow: visible; }}
  table {{ min-width: 0; }}
  a {{ color: inherit; text-decoration: none; }}
}}
</style>
</head>
<body>
<main>
<h1>logsieve diagnosis</h1>
<p class="meta">Generated {generated}<br>
{report.event_count} events, {report.error_count} error or critical</p>
<h2>Run</h2>
<p class="meta">Inputs</p>
<ul>{inputs}</ul>
{_p("Redaction: " + report.redaction_note)}
{_p("Vault: " + report.vault_note)}
{_p("LLM: " + report.llm_note)}
<h2>Suspected root cause</h2>
{cause}
<h2>Next steps</h2>
<ul>{steps}</ul>
{explained}
{separate}
{notes}
<h2>Matched patterns</h2>
{patterns}
<h2>Error timeline</h2>
{timeline}
<h2>Warnings</h2>
{warnings}
{model}
<h2>Limitations</h2>
{limits}
</main>
</body>
</html>
"""


JSON_SCHEMA_VERSION = 1


def _finding_json(finding: Finding) -> dict:
    pattern = finding.pattern
    return {
        "id": pattern.id,
        "title": pattern.title,
        "match": pattern.code_label,
        "area": pattern.area,
        "category": pattern.category,
        "severity": pattern.severity,
        "confidence": pattern.confidence,
        "uncertain": pattern.uncertain,
        "events": finding.count,
        "samples": list(finding.samples),
        "checks": list(pattern.fix_hints),
        "sources": list(pattern.sources),
    }


def render_json(report: Report) -> str:
    """Machine-readable report. Built from the same redacted fields as Markdown and HTML."""
    diagnosis = report.diagnosis
    errors = [event for event in report.events if event.severity in {"error", "critical"}]
    document = {
        "schema": JSON_SCHEMA_VERSION,
        "tool": "logsieve",
        "generated": format_timestamp(report.generated),
        "inputs": list(report.inputs),
        "events": report.event_count,
        "errors": report.error_count,
        "redaction": report.redaction_note,
        "vault": report.vault_note,
        "llm": report.llm_note,
        "suspected_cause": _finding_json(diagnosis.primary) if diagnosis.primary else None,
        "ranking_confidence": diagnosis.confidence,
        "narrative": diagnosis.narrative,
        "next_steps": list(diagnosis.steps),
        "supporting": [item.pattern.id for item in diagnosis.supporting],
        "consistent_with_cause": [item.pattern.id for item in diagnosis.explained],
        "separate_findings": [item.pattern.id for item in diagnosis.independent],
        "notes": [item.pattern.id for item in diagnosis.annotations],
        "findings": [_finding_json(item) for item in diagnosis.findings],
        "timeline": [
            {
                "time": format_timestamp(event.timestamp) or None,
                "severity": event.severity,
                "source": _basename(event),
                "user": event.display_user or "",
                "message": event.display_message or "",
            }
            for event in errors[:200]
        ],
        "timeline_truncated": len(errors) > 200,
        "warnings": list(report.warnings),
        "model_note": report.llm_answer.strip() if report.llm_answer else None,
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)