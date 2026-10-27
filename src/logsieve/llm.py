"""Optional OpenAI-compatible chat completion.

The caller builds the payload from redacted text and leak-checks it before
this module is allowed to open a socket. ``--show-payload`` prints the same
JSON this module would post.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from logsieve.cause import Diagnosis, format_timestamp
from logsieve.models import LogEvent

DEFAULT_URL = "http://127.0.0.1:11434/v1"
DEFAULT_MODEL = "llama3.2"
MAX_EVENTS = 80
MAX_MESSAGE = 400
MAX_JSON = 24_000

SYSTEM_PROMPT = (
    "You help a Windows endpoint administrator read a pseudonymized diagnosis. "
    "Tokens that look like LS_EMAIL_1, LS_HOST_2, LS_USER_3, LS_SID_1, LS_IPV4_1, "
    "LS_IPV6_1, LS_GUID_1, LS_DOMAIN_1, or LS_SECRET_1 stand in for identifiers. "
    "Do not guess what they were. "
    "When a pattern explanation is included, treat it as the authority for that error code. "
    "If the evidence is uncertain, say so. "
    "Do not invent Knowledge Base article numbers. "
    "Suggest checks. Do not suggest changing the device unless you clearly label the suggestion "
    "as a change the operator would have to make themselves."
)


class LlmError(Exception):
    """The model endpoint did not return a completion. The report can still be written."""


def endpoint(base: str) -> str:
    trimmed = base.rstrip("/")
    if trimmed.endswith("/chat/completions"):
        return trimmed
    return trimmed + "/chat/completions"


def payload_text(payload: dict) -> str:
    """The exact JSON body that would be posted."""
    return json.dumps(payload, ensure_ascii=True)


def build_user_text(diagnosis: Diagnosis, events: list[LogEvent]) -> str:
    lines: list[str] = []
    primary = diagnosis.primary
    if primary is None:
        lines.append("Suspected cause: none")
        lines.append(diagnosis.narrative)
    else:
        pattern = primary.pattern
        lines.append(
            f"Suspected cause: {pattern.title} ({pattern.id}, {pattern.code_label})"
        )
        lines.append(
            f"Ranking confidence: {diagnosis.confidence}. Pattern confidence: {pattern.confidence}."
            f" Uncertain: {'yes' if pattern.uncertain else 'no'}."
        )
        lines.append("Explanation:")
        lines.append(pattern.explanation.strip())
    if diagnosis.supporting or diagnosis.explained or diagnosis.independent or diagnosis.annotations:
        lines.append("Other matches:")
        for finding in (
            diagnosis.supporting + diagnosis.explained + diagnosis.independent + diagnosis.annotations
        ):
            pattern = finding.pattern
            lines.append(
                f"- {pattern.title} ({pattern.id}, {pattern.code_label},"
                f" confidence {pattern.confidence}, uncertain {'yes' if pattern.uncertain else 'no'},"
                f" count {finding.count})"
            )
            lines.append(pattern.explanation.strip())
    lines.append("Checks already suggested locally:")
    lines.extend(f"- {step}" for step in diagnosis.steps)
    lines.append("Redacted error timeline:")
    shown = 0
    for event in events:
        if event.severity not in {"error", "critical"}:
            continue
        if shown >= MAX_EVENTS:
            lines.append(f"[further error events omitted after {MAX_EVENTS}]")
            break
        message = (event.display_message or "").replace("\n", " ").strip()
        user = (event.display_user or "").strip()
        if user:
            message = f"user={user} {message}"
        if len(message) > MAX_MESSAGE:
            message = message[: MAX_MESSAGE - 3] + "..."
        name = (event.display_source or "").replace("\\", "/").rsplit("/", 1)[-1]
        host = (event.display_host or "").strip()
        if host:
            message = f"host={host} {message}"
        if len(message) > MAX_MESSAGE:
            message = message[: MAX_MESSAGE - 3] + "..."
        lines.append(
            f"- {format_timestamp(event.timestamp)} {event.severity} {name} {message}".strip()
        )
        shown += 1
    if shown == 0:
        lines.append("- none")
    return "\n".join(lines)


def build_payload(model: str, user_text: str) -> dict:
    payload = {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_text},
        ],
    }
    encoded = payload_text(payload)
    if len(encoded) > MAX_JSON:
        overflow = len(encoded) - MAX_JSON
        user_text = user_text[: max(0, len(user_text) - overflow - 16)].rstrip() + "\n[truncated]"
        payload["messages"][1]["content"] = user_text
    return payload


def complete(base_url: str, payload: dict, timeout: float, api_key: str | None = None) -> str:
    body = payload_text(payload).encode("ascii")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    request = urllib.request.Request(endpoint(base_url), data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise LlmError(f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise LlmError(f"could not reach the model ({exc.reason})") from exc
    except TimeoutError as exc:
        raise LlmError("the model request timed out") from exc
    try:
        parsed = json.loads(raw.decode("utf-8"))
        content = parsed["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise LlmError("the model response was not a chat completion") from exc
    if not isinstance(content, str) or not content.strip():
        raise LlmError("the model returned an empty completion")
    return content.strip()