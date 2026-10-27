"""Command line for diagnose, reveal, demo, and the pattern list."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from logsieve import __version__
from logsieve.demo import run_demo
from logsieve.errors import LogsieveError
from logsieve.llm import DEFAULT_MODEL, DEFAULT_URL, payload_text
from logsieve.patterns import load_builtin, load_patterns
from logsieve.patterns.matcher import LIBRARY_DIR
from logsieve.pipeline import execute, passphrase_from_env
from logsieve.pseudo import RedactOptions, load_mapping


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsieve",
        description="Local diagnosis for ConfigMgr, Intune, and Windows event logs.",
    )
    parser.add_argument("--version", action="version", version=f"logsieve {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    diagnose = commands.add_parser("diagnose", help="read logs and write a redacted report")
    diagnose.add_argument("paths", nargs="+", type=Path, help="log files or directories")
    diagnose.add_argument("--output", type=Path, help="report file or directory")
    diagnose.add_argument("--format", choices=("md", "html", "both"), dest="fmt")
    diagnose.add_argument("--vault", type=Path, help="write an encrypted mapping here")
    diagnose.add_argument("--vault-key", type=Path, help="Fernet key file (default: <vault>.key)")
    diagnose.add_argument(
        "--parser",
        default="auto",
        choices=("auto", "cmtrace", "ime", "evtx", "event-xml", "event-csv", "journald", "plain"),
    )
    diagnose.add_argument("--keep-guids", action="store_true", help="leave GUIDs visible")
    diagnose.add_argument("--keep-ips", action="store_true", help="leave IP addresses visible")
    diagnose.add_argument("--no-redact", action="store_true", help="do not pseudonymize; refuses --llm")
    diagnose.add_argument("--hostname", action="append", default=[], help="extra hostname to mask (repeatable)")
    diagnose.add_argument("--username", action="append", default=[], help="extra account to mask (repeatable)")
    diagnose.add_argument("--pattern-dir", type=Path, help="extra YAML patterns")
    diagnose.add_argument(
        "--llm",
        nargs="?",
        const=DEFAULT_URL,
        default=None,
        help=f"send the redacted payload to an OpenAI-compatible URL (default {DEFAULT_URL})",
    )
    diagnose.add_argument("--llm-model", default=DEFAULT_MODEL)
    diagnose.add_argument("--llm-timeout", type=float, default=60)
    diagnose.add_argument(
        "--show-payload",
        action="store_true",
        help="print the JSON body that would be sent and do not call the network",
    )
    diagnose.set_defaults(func=_diagnose)

    reveal = commands.add_parser("reveal", help="restore tokens in a file or stdin")
    reveal.add_argument("--vault", type=Path, required=True)
    reveal.add_argument("--vault-key", type=Path)
    reveal.add_argument("--input", type=Path, help="text to reveal (default: stdin)")
    reveal.add_argument("--output", type=Path, help="write here (default: stdout)")
    reveal.set_defaults(func=_reveal)

    demo = commands.add_parser("demo", help="diagnose bundled fictional logs, offline")
    demo.add_argument("--output", type=Path, default=Path("logsieve-demo-out"))
    demo.set_defaults(func=_demo)

    patterns = commands.add_parser("patterns", help="list the built-in pattern library")
    patterns.add_argument("--pattern-dir", type=Path)
    patterns.set_defaults(func=_patterns)
    return parser


def _resolve_format(output: Path | None, fmt: str | None) -> str:
    if fmt:
        return fmt
    if output is None:
        return "md"
    if output.suffix.lower() == ".html":
        return "html"
    if output.suffix.lower() in {".md", ".markdown"}:
        return "md"
    return "both"


def _vault_key(vault: Path | None, vault_key: Path | None, passphrase: str | None) -> Path | None:
    if passphrase or vault is None:
        return vault_key
    if vault_key is not None:
        return vault_key
    return Path(str(vault) + ".key")


def _diagnose(args: argparse.Namespace) -> int:
    passphrase = passphrase_from_env()
    options = RedactOptions(
        enabled=not args.no_redact,
        guids=not args.keep_guids,
        ips=not args.keep_ips,
        extra_hosts=list(args.hostname),
        extra_users=list(args.username),
    )
    fmt = _resolve_format(args.output, args.fmt)
    outcome = execute(
        list(args.paths),
        parser=args.parser,
        options=options,
        pattern_dirs=[args.pattern_dir] if args.pattern_dir else None,
        vault=args.vault,
        vault_key=_vault_key(args.vault, args.vault_key, passphrase),
        passphrase=passphrase,
        output=args.output,
        fmt=fmt,
        llm_url=args.llm,
        llm_model=args.llm_model,
        llm_timeout=args.llm_timeout,
        llm_api_key=os_api_key(),
        show_payload=args.show_payload,
    )
    if outcome.report_leaks:
        print(
            "logsieve: refusing to write the report because an original identifier is still visible",
            file=sys.stderr,
        )
        return 2
    if outcome.payload_leaks and (args.show_payload or args.llm):
        print(
            "logsieve: refusing to show or send the model payload because an original identifier is still visible",
            file=sys.stderr,
        )
        return 2
    if args.show_payload:
        if outcome.payload is None:
            raise LogsieveError("no payload was built", code=2)
        sys.stdout.write(payload_text(outcome.payload) + "\n")
        print("logsieve: model payload is on stdout; nothing was sent", file=sys.stderr)
        return 0
    if outcome.llm_error:
        print(f"logsieve: model request failed ({outcome.llm_error})", file=sys.stderr)
        if args.output is None:
            sys.stdout.write(outcome.markdown)
        return 3
    if args.output is None:
        sys.stdout.write(outcome.markdown)
    return 0


def os_api_key() -> str | None:
    import os

    value = os.environ.get("LOGSIEVE_LLM_API_KEY")
    if value is None or value == "":
        return None
    return value


def _reveal(args: argparse.Namespace) -> int:
    passphrase = passphrase_from_env()
    key = _vault_key(args.vault, args.vault_key, passphrase)
    mapping = load_mapping(args.vault, passphrase=passphrase, key_path=key)
    if args.input is not None:
        text = args.input.read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()
    revealed = mapping.reveal(text)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(revealed, encoding="utf-8")
    else:
        sys.stdout.write(revealed)
        if revealed and not revealed.endswith("\n"):
            sys.stdout.write("\n")
    return 0


def _demo(args: argparse.Namespace) -> int:
    return run_demo(args.output)


def _patterns(args: argparse.Namespace) -> int:
    if args.pattern_dir:
        patterns = load_patterns(LIBRARY_DIR, args.pattern_dir)
    else:
        patterns = load_builtin()
    for pattern in patterns:
        flag = " uncertain" if pattern.uncertain else ""
        print(f"{pattern.id}\t{pattern.code_label}\t{pattern.confidence}{flag}\t{pattern.title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 0
    try:
        return int(args.func(args))
    except LogsieveError as exc:
        print(f"logsieve: {exc}", file=sys.stderr)
        return exc.code
    except BrokenPipeError:
        return 0
