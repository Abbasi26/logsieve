from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from logsieve.errors import LogsieveError

DEFAULT_ITERATIONS = 200_000


def _restrict(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


class Mapping:
    """In-memory identifier to token map. Stable for one vault."""

    def __init__(self) -> None:
        self.entries: list[dict[str, str]] = []
        self._by_key: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}

    def token(self, category: str, key: str, original: str) -> str:
        slot = (category, key)
        existing = self._by_key.get(slot)
        if existing:
            return existing
        number = self._counters.get(category, 0) + 1
        self._counters[category] = number
        issued = f"LS_{category}_{number}"
        self._by_key[slot] = issued
        self.entries.append(
            {"category": category, "key": key, "token": issued, "original": original}
        )
        return issued

    def reveal(self, text: str) -> str:
        if not text or not self.entries:
            return text
        ordered = sorted(self.entries, key=lambda item: len(item["token"]), reverse=True)
        lookup = {item["token"]: item["original"] for item in ordered}
        import re

        pattern = re.compile("|".join(re.escape(item["token"]) for item in ordered))
        return pattern.sub(lambda match: lookup[match.group(0)], text)

    def to_json(self) -> bytes:
        payload = {"version": 1, "entries": self.entries}
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> Mapping:
        data = json.loads(raw.decode("utf-8"))
        mapping = cls()
        for entry in data.get("entries", []):
            category = entry["category"]
            key = entry["key"]
            token = entry["token"]
            original = entry["original"]
            mapping.entries.append(
                {"category": category, "key": key, "token": token, "original": original}
            )
            mapping._by_key[(category, key)] = token
            try:
                number = int(token.rsplit("_", 1)[-1])
            except ValueError:
                number = 0
            mapping._counters[category] = max(mapping._counters.get(category, 0), number)
        return mapping


def _fernet_from_passphrase(passphrase: str, salt: bytes, iterations: int) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
    return Fernet(key)


def save_mapping(
    mapping: Mapping,
    path: Path,
    *,
    passphrase: str | None = None,
    key_path: Path | None = None,
    iterations: int = DEFAULT_ITERATIONS,
) -> None:
    """Encrypt ``mapping`` to ``path``.

    A passphrase uses PBKDF2-HMAC-SHA256. Without one, a Fernet key is written
    to ``key_path`` (mode 0600 on POSIX). The vault file never stores the key.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if passphrase:
        salt = os.urandom(16)
        fernet = _fernet_from_passphrase(passphrase, salt, iterations)
        envelope = {
            "logsieve_vault": 1,
            "kdf": "pbkdf2-sha256",
            "iterations": iterations,
            "salt": base64.b64encode(salt).decode("ascii"),
            "ciphertext": fernet.encrypt(mapping.to_json()).decode("ascii"),
        }
    else:
        if key_path is None:
            raise LogsieveError("a vault key path is required when no passphrase is set")
        if key_path.exists():
            key = key_path.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            key_path.write_bytes(key + b"\n")
            _restrict(key_path)
        fernet = Fernet(key)
        envelope = {
            "logsieve_vault": 1,
            "kdf": "fernet-keyfile",
            "ciphertext": fernet.encrypt(mapping.to_json()).decode("ascii"),
        }
    path.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    _restrict(path)


def load_mapping(
    path: Path,
    *,
    passphrase: str | None = None,
    key_path: Path | None = None,
) -> Mapping:
    if not path.exists():
        raise LogsieveError(f"vault not found: {path}")
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise LogsieveError(f"vault is not a logsieve file: {path}") from exc
    if envelope.get("logsieve_vault") != 1:
        raise LogsieveError(f"unrecognised vault version in {path}")
    kdf = envelope.get("kdf")
    try:
        if kdf == "pbkdf2-sha256":
            if not passphrase:
                raise LogsieveError(
                    "this vault is passphrase-encrypted; set LOGSIEVE_VAULT_PASSPHRASE"
                )
            salt = base64.b64decode(envelope["salt"])
            fernet = _fernet_from_passphrase(passphrase, salt, int(envelope["iterations"]))
        elif kdf == "fernet-keyfile":
            if passphrase:
                raise LogsieveError(
                    "this vault was created with a key file; unset LOGSIEVE_VAULT_PASSPHRASE"
                )
            if key_path is None or not key_path.exists():
                raise LogsieveError(f"vault key file not found for {path}")
            fernet = Fernet(key_path.read_bytes().strip())
        else:
            raise LogsieveError(f"unsupported vault kdf: {kdf}")
        raw = fernet.decrypt(envelope["ciphertext"].encode("ascii"))
    except LogsieveError:
        raise
    except (InvalidToken, KeyError, ValueError) as exc:
        raise LogsieveError("could not decrypt the vault (wrong key or passphrase)") from exc
    return Mapping.from_json(raw)