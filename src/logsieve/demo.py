"""Offline demo on bundled fictional logs.

The story is a laptop in the reserved example domain that cannot resolve its
update server, plus a content hash mismatch and an uncertain Intune detection
code. Nothing here is a real tenant.
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from logsieve.errors import LogsieveError
from logsieve.parsers.synthetic_evtx import build_evtx
from logsieve.pipeline import execute
from logsieve.pseudo import RedactOptions, find_leaks

DEMO_LOGS = Path(__file__).resolve().parent / "demo_logs"
EMAIL = "ada.example@northwind.example"
IDENTIFIERS = (
    EMAIL,
    "laptop-07.northwind.example",
    "wsus.northwind.example",
    "mp01.northwind.example",
    "jump-01.northwind.example",
    "S-1-5-21-1000000001-1000000002-1000000003-1001",
    "203.0.113.25",
    "203.0.113.10",
    "2001:db8:1::25",
    "11111111-2222-4333-8444-555555555555",
    "fictional-secret-value",
    "NORTHWIND\\ada.example",
    "laptop-07",
    "northwind",
)


def run_demo(output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    log_dir = output / "logs"
    if log_dir.exists():
        shutil.rmtree(log_dir)
    log_dir.mkdir()
    if not DEMO_LOGS.is_dir():
        raise LogsieveError(f"bundled demo logs are missing: {DEMO_LOGS}")
    for path in sorted(DEMO_LOGS.iterdir()):
        if path.is_file():
            shutil.copy(path, log_dir / path.name)
    when = datetime(2026, 10, 21, 8, 2, 11, tzinfo=timezone.utc)
    evtx = build_evtx(
        [
            {
                "provider": "Microsoft-Windows-WindowsUpdateClient",
                "event_id": "20",
                "level": "2",
                "computer": "laptop-07.northwind.example",
                "time": "2026-10-21T08:02:11.0000000Z",
                "when": when,
                "user": "S-1-5-21-1000000001-1000000002-1000000003-1001",
                "message": (
                    "Installation Failure: Windows failed to install the following update"
                    " with error 0x8024402C."
                ),
            }
        ]
    )
    (log_dir / "WindowsUpdate.evtx").write_bytes(evtx)
    vault = output / "logsieve-vault.json"
    key = Path(str(vault) + ".key")
    outcome = execute(
        [log_dir],
        options=RedactOptions(),
        vault=vault,
        vault_key=key,
        output=output,
        fmt="both",
    )
    report = outcome.markdown + "\n" + outcome.html
    leaks = find_leaks(report, outcome.mapping) if outcome.report_leaks == 0 else ["hidden"]
    planted = [item for item in IDENTIFIERS if item.casefold() in report.casefold()]
    if outcome.report_leaks or leaks or planted or not outcome.wrote:
        raise LogsieveError(
            "demo report failed the leak check; the report was not trusted",
            code=2,
        )
    email = next((entry for entry in outcome.mapping.entries if entry["original"] == EMAIL), None)
    if email is None:
        raise LogsieveError("demo did not pseudonymize the fictional account")
    revealed = outcome.mapping.reveal(f"The account was {email['token']}.")
    expected = f"The account was {EMAIL}."
    if revealed != expected:
        raise LogsieveError("reveal did not restore the fictional demo account")
    if "0x8024402C" not in outcome.markdown:
        raise LogsieveError("demo report lost the Windows Update code")
    if not any(event.source_type == "evtx" for event in outcome.events):
        raise LogsieveError("demo did not read the synthetic event log")
    primary = outcome.diagnosis.primary
    title = primary.pattern.title if primary else "no pattern matched"
    confidence = outcome.diagnosis.confidence
    print(f"suspected cause: {title}")
    if primary is not None:
        print(f"pattern: {primary.pattern.id}  confidence: {confidence}")
    print("timeline:")
    shown = 0
    for event in outcome.events:
        if event.severity not in {"error", "critical"}:
            continue
        message = (event.display_message or "").replace("\n", " ")
        if len(message) > 140:
            message = message[:137] + "..."
        stamp = event.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if event.timestamp else ""
        name = (event.display_source or "").replace("\\", "/").rsplit("/", 1)[-1]
        print(f"  {stamp}  {event.severity}  {name}  {message}")
        shown += 1
        if shown >= 4:
            break
    print(f"reveal: The account was {email['token']}. -> {revealed}")
    print("report leak check: clean")
    print("llm: off")
    for path in outcome.wrote:
        print(f"report: {path}")
    print(f"vault: {vault}")
    return 0