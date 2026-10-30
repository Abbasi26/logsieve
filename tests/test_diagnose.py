import json
import urllib.request
from pathlib import Path


from logsieve.cli import main
from logsieve.demo import DEMO_LOGS, EMAIL, IDENTIFIERS
from logsieve.parsers.synthetic_evtx import build_evtx
from datetime import datetime, timezone


SECRETS = IDENTIFIERS


def _write_evtx(directory: Path) -> None:
    when = datetime(2026, 10, 21, 8, 2, 11, tzinfo=timezone.utc)
    blob = build_evtx(
        [
            {
                "provider": "Microsoft-Windows-WindowsUpdateClient",
                "event_id": "20",
                "level": "2",
                "computer": "laptop-07.northwind.example",
                "time": "2026-10-21T08:02:11.0000000Z",
                "when": when,
                "user": "S-1-5-21-1000000001-1000000002-1000000003-1001",
                "message": "Installation Failure: Windows failed to install the following update with error 0x8024402C.",
            }
        ]
    )
    (directory / "WindowsUpdate.evtx").write_bytes(blob)


def test_show_payload_has_no_originals(tmp_path: Path, monkeypatch, capsys):
    def boom(*_args, **_kwargs):
        raise AssertionError("urlopen should not be called")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    for path in DEMO_LOGS.iterdir():
        if path.is_file():
            (log_dir / path.name).write_bytes(path.read_bytes())
    _write_evtx(log_dir)
    out = tmp_path / "out"
    code = main(["diagnose", str(log_dir), "--show-payload", "--output", str(out), "--llm", "http://127.0.0.1:9/v1"])
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["temperature"] == 0.1
    blob = json.dumps(payload)
    for secret in SECRETS:
        assert secret not in blob
        assert secret.casefold() not in blob.casefold()
    assert "0x8024402C" in blob
    report = (out / "report.md").read_text(encoding="utf-8")
    html = (out / "report.html").read_text(encoding="utf-8")
    for secret in SECRETS:
        assert secret.casefold() not in report.casefold()
        assert secret.casefold() not in html.casefold()
    assert "0x8024402C" in report
    assert "collector.jsonl" in report
    cause = report.split("## Suspected root cause", 1)[1].split("## Next steps", 1)[0]
    separate = report.split("## Separate findings", 1)[1].split("\n## ", 1)[0]
    notes = report.split("## Notes that are not the cause", 1)[1].split("\n## ", 1)[0]
    assert "wu-name-not-resolved" in cause
    assert "hash-value-incorrect" in separate
    assert "intune-not-detected" in separate
    assert "wu-event-20" in notes
    assert "wu-event-20" not in cause


def test_no_redact_refuses_llm(tmp_path: Path, monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("urlopen should not be called")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    log = tmp_path / "notes.log"
    log.write_text("2026-10-21T08:01:05Z ERROR failed 0x8024402C\n", encoding="utf-8")
    code = main(["diagnose", str(log), "--no-redact", "--llm"])
    assert code == 2
    code = main(["diagnose", str(log), "--no-redact", "--show-payload"])
    assert code == 2


def test_demo_command(tmp_path: Path, capsys):
    out = tmp_path / "demo"
    code = main(["demo", "--output", str(out)])
    captured = capsys.readouterr()
    assert code == 0
    assert "report leak check: clean" in captured.out
    assert "llm: off" in captured.out
    assert EMAIL in captured.out
    assert "LS_EMAIL_" in captured.out
    assert (out / "report.html").is_file()
    assert (out / "report.md").is_file()
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "0x8024402C" in html
    assert EMAIL not in html
    assert "viewport" in html
    assert "#f6f3ec" in html


def test_reveal_round_trip(tmp_path: Path, capsys):
    log = tmp_path / "notes.log"
    log.write_text(
        "2026-10-21T08:01:05Z ERROR user ada.example@northwind.example failed 0x8024402C\n",
        encoding="utf-8",
    )
    vault = tmp_path / "vault.json"
    out = tmp_path / "out"
    code = main(["diagnose", str(log), "--vault", str(vault), "--output", str(out)])
    assert code == 0
    report = (out / "report.md").read_text(encoding="utf-8")
    assert EMAIL not in report
    token = report.split("LS_EMAIL_", 1)[1].split()[0]
    # The cell may end at a pipe.
    token = "LS_EMAIL_" + token.strip("|").strip()
    revealed = tmp_path / "revealed.txt"
    code = main(["reveal", "--vault", str(vault), "--input", str(out / "report.md"), "--output", str(revealed)])
    assert code == 0
    text = revealed.read_text(encoding="utf-8")
    assert EMAIL in text
    assert token not in text or EMAIL in text
    capsys.readouterr()


def test_wrong_passphrase_on_reveal(tmp_path: Path, monkeypatch):
    log = tmp_path / "notes.log"
    log.write_text("2026-10-21T08:01:05Z ERROR host laptop-07.northwind.example\n", encoding="utf-8")
    vault = tmp_path / "vault.json"
    monkeypatch.setenv("LOGSIEVE_VAULT_PASSPHRASE", "correct horse")
    # The CLI uses the default iteration count. Call the library the CLI uses
    # only through diagnose, which is slow at 200k. Use a direct save in the
    # vault test. Here, confirm the CLI refuses a missing passphrase match by
    # creating the vault through diagnose and then changing the env.
    code = main(["diagnose", str(log), "--vault", str(vault), "--output", str(tmp_path / "out.md")])
    assert code == 0
    monkeypatch.setenv("LOGSIEVE_VAULT_PASSPHRASE", "wrong")
    code = main(["reveal", "--vault", str(vault), "--input", str(tmp_path / "out.md")])
    assert code == 1


def test_empty_file_exits_zero(tmp_path: Path):
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    code = main(["diagnose", str(log)])
    assert code == 0


def test_missing_input_exits_one(tmp_path: Path):
    code = main(["diagnose", str(tmp_path / "missing.log")])
    assert code == 1

def test_vault_path_user_is_redacted(tmp_path: Path):
    home = tmp_path / "Users" / "ada.example"
    home.mkdir(parents=True)
    log = home / "notes.log"
    log.write_text("2026-10-21T08:01:05Z ERROR failed 0x8024402C\n", encoding="utf-8")
    vault = home / "vault.json"
    out = tmp_path / "out"
    code = main(["diagnose", str(log), "--vault", str(vault), "--output", str(out)])
    assert code == 0
    report = (out / "report.md").read_text(encoding="utf-8")
    assert "ada.example" not in report
    assert "LS_USER_" in report