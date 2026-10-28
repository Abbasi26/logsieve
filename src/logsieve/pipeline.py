"""Parse, match, redact, rank, and render one diagnose run."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from logsieve.cause import Diagnosis, build_diagnosis
from logsieve.errors import LogsieveError
from logsieve.llm import LlmError, build_payload, build_user_text, complete
from logsieve.models import LogEvent
from logsieve.parsers import iter_input_files, parse_path
from logsieve.patterns.matcher import LIBRARY_DIR, load_patterns, match_events
from logsieve.pseudo import Mapping, RedactOptions, Session, find_leaks, save_mapping
from logsieve.pseudo.vault import DEFAULT_ITERATIONS
from logsieve.report import Report, redaction_note, render_html, render_markdown, utcnow


@dataclass
class Outcome:
    markdown: str
    html: str
    payload: dict | None
    report_leaks: int
    payload_leaks: int
    llm_error: str | None
    events: list[LogEvent]
    diagnosis: Diagnosis
    warnings: list[str]
    mapping: Mapping
    wrote: list[Path] = field(default_factory=list)


def _sort_key(event: LogEvent) -> tuple:
    stamp = event.timestamp
    if stamp is None:
        return (1, timedelta(0), event.order)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return (0, stamp - datetime(1970, 1, 1, tzinfo=timezone.utc), event.order)


def collect_events(paths: list[Path], parser: str) -> tuple[list[LogEvent], list[str]]:
    try:
        files = iter_input_files(paths)
    except FileNotFoundError as exc:
        raise LogsieveError(f"input not found: {exc}") from exc
    if not files:
        raise LogsieveError("no input files")
    events: list[LogEvent] = []
    warnings: list[str] = []
    order = 0
    for path in files:
        try:
            parsed = parse_path(path, parser)
        except LogsieveError as exc:
            warnings.append(f"{path}: {exc}")
            continue
        except Exception as exc:
            warnings.append(f"{path}: {exc}")
            continue
        warnings.extend(parsed.warnings)
        for event in parsed.events:
            event.order = order
            order += 1
            events.append(event)
    if not events and warnings:
        raise LogsieveError("no events parsed\n" + "\n".join(warnings))
    events.sort(key=_sort_key)
    return events, warnings


def _warm(session: Session, events: list[LogEvent]) -> None:
    blobs: list[str] = []
    for event in events:
        session.observe_host(event.host)
        session.observe_user(event.user)
        blobs.append(
            "\n".join(
                part
                for part in (
                    event.source_file,
                    event.host,
                    event.user,
                    event.component,
                    event.provider,
                    event.message,
                )
                if part
            )
        )
    for _ in range(4):
        before = (len(session.short_hosts), len(session.extra_users), len(session.mapping.entries))
        for blob in blobs:
            session.redact(blob)
        after = (len(session.short_hosts), len(session.extra_users), len(session.mapping.entries))
        if after == before:
            break
    for event in events:
        event.display_source = session.redact(event.source_file)
        event.display_host = session.redact(event.host)
        event.display_user = session.redact(event.user)
        event.display_component = session.redact(event.component)
        event.display_message = session.redact(event.message)


def _basename_display(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def write_reports(output: Path, fmt: str, markdown: str, html: str) -> list[Path]:
    wrote: list[Path] = []
    treat_as_dir = output.is_dir() or (not output.exists() and output.suffix == "")
    if treat_as_dir:
        output.mkdir(parents=True, exist_ok=True)
        if fmt in {"md", "both"}:
            path = output / "report.md"
            path.write_text(markdown, encoding="utf-8")
            wrote.append(path)
        if fmt in {"html", "both"}:
            path = output / "report.html"
            path.write_text(html, encoding="utf-8")
            wrote.append(path)
        return wrote
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "both":
        md_path = output if output.suffix.lower() == ".md" else output.with_suffix(".md")
        html_path = output if output.suffix.lower() == ".html" else output.with_suffix(".html")
        if md_path == html_path:
            html_path = output.with_name(output.name + ".html")
        md_path.write_text(markdown, encoding="utf-8")
        html_path.write_text(html, encoding="utf-8")
        return [md_path, html_path]
    text = html if fmt == "html" else markdown
    output.write_text(text, encoding="utf-8")
    return [output]


def execute(
    paths: list[Path],
    *,
    parser: str = "auto",
    options: RedactOptions | None = None,
    pattern_dirs: list[Path] | None = None,
    vault: Path | None = None,
    vault_key: Path | None = None,
    passphrase: str | None = None,
    iterations: int = DEFAULT_ITERATIONS,
    output: Path | None = None,
    fmt: str = "md",
    llm_url: str | None = None,
    llm_model: str = "llama3.2",
    llm_timeout: float = 60,
    llm_api_key: str | None = None,
    show_payload: bool = False,
) -> Outcome:
    options = options or RedactOptions()
    if (llm_url or show_payload) and not options.enabled:
        raise LogsieveError(
            "refusing to build or send a model payload when redaction is off",
            code=2,
        )
    events, warnings = collect_events(paths, parser)
    directories = [LIBRARY_DIR, *(pattern_dirs or [])]
    patterns = load_patterns(*directories)
    hits = match_events(events, patterns)
    session = Session(options=options)
    _warm(session, events)
    warnings = [session.redact(item) for item in warnings]
    diagnosis = build_diagnosis(events, hits)
    if vault is not None and options.enabled:
        save_mapping(
            session.mapping,
            vault,
            passphrase=passphrase,
            key_path=vault_key,
            iterations=iterations,
        )
        shown_vault = session.redact(str(vault))
        if passphrase:
            vault_note = (
                f"saved to {shown_vault} using the passphrase in LOGSIEVE_VAULT_PASSPHRASE."
                " The passphrase is not in this report."
            )
        else:
            shown_key = session.redact(str(vault_key or ""))
            vault_note = (
                f"saved to {shown_vault}. The key file is {shown_key}."
                " logsieve reveal reads that file. The key is not in this report."
            )
    elif not options.enabled:
        vault_note = "not written because redaction is off."
    else:
        vault_note = (
            "not saved. The mapping existed only in this process."
            " reveal cannot restore these tokens later. Pass --vault to keep an encrypted copy."
        )
    llm_note = "off. No text was sent anywhere."
    if show_payload and not llm_url:
        llm_note = "not called. --show-payload prints the request body and nothing is sent."
    elif llm_url and show_payload:
        llm_note = f"the request body for {llm_url} is on stdout. Nothing is sent when --show-payload is set."
    report = Report(
        generated=utcnow(),
        inputs=[_basename_display(event.display_source or event.source_file) for event in _unique_inputs(events)],
        event_count=len(events),
        error_count=sum(1 for event in events if event.severity in {"error", "critical"}),
        redaction_note=redaction_note(options),
        vault_note=vault_note,
        llm_note=llm_note,
        diagnosis=diagnosis,
        events=events,
        warnings=warnings,
    )
    # Inputs listed once per source file, in first-seen order, already redacted via display_source.
    markdown = render_markdown(report)
    html = render_html(report)
    report_leaks = len(find_leaks(markdown + "\n" + html, session.mapping)) if options.enabled else 0
    payload = None
    payload_leaks = 0
    llm_error = None
    if options.enabled:
        payload = build_payload(llm_model, build_user_text(diagnosis, events))
        blob = "\n".join(message["content"] for message in payload["messages"])
        payload_leaks = len(find_leaks(blob, session.mapping))
    if report_leaks == 0 and payload_leaks == 0 and llm_url and not show_payload and payload is not None:
        try:
            answer = complete(llm_url, payload, llm_timeout, api_key=llm_api_key)
        except LlmError as exc:
            llm_error = str(exc)
            report.llm_note = f"the request to {llm_url} failed ({llm_error}). This report was still written."
            report.llm_answer = None
            markdown = render_markdown(report)
            html = render_html(report)
        else:
            report.llm_note = (
                f"a completion was requested from {llm_url} model {llm_model}."
                " Only the redacted payload was sent."
            )
            report.llm_answer = answer
            markdown = render_markdown(report)
            html = render_html(report)
            report_leaks = len(find_leaks(markdown + "\n" + html, session.mapping))
    wrote: list[Path] = []
    if output is not None and report_leaks == 0:
        wrote = write_reports(output, fmt, markdown, html)
    return Outcome(
        markdown=markdown,
        html=html,
        payload=payload,
        report_leaks=report_leaks,
        payload_leaks=payload_leaks,
        llm_error=llm_error,
        events=events,
        diagnosis=diagnosis,
        warnings=warnings,
        mapping=session.mapping,
        wrote=wrote,
    )


def _unique_inputs(events: list[LogEvent]) -> list[LogEvent]:
    seen: set[str] = set()
    chosen: list[LogEvent] = []
    for event in events:
        key = event.source_file
        if key in seen:
            continue
        seen.add(key)
        chosen.append(event)
    return chosen


def passphrase_from_env() -> str | None:
    value = os.environ.get("LOGSIEVE_VAULT_PASSPHRASE")
    if value is None or value == "":
        return None
    return value
