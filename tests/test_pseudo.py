import os
import stat
from pathlib import Path

import pytest

from logsieve.errors import LogsieveError
from logsieve.pseudo import Mapping, RedactOptions, Session, find_leaks, load_mapping, save_mapping

EMAIL = "ada.example@northwind.example"
SID = "S-1-5-21-1000000001-1000000002-1000000003-1001"
IPV4 = "203.0.113.25"
IPV6 = "2001:db8:1::25"
GUID = "{11111111-2222-4333-8444-555555555555}"
HOST = "laptop-07.northwind.example"
SECRET = "fictional-secret-value"
TEXT = (
    f"user {EMAIL} sid {SID} v4 {IPV4} v6 {IPV6} guid {GUID} host {HOST} "
    f"acct NORTHWIND\\ada.example path C:\\Users\\ada.example\\Desktop "
    f"password={SECRET}"
)


def test_round_trip_one_spelling_each():
    session = Session()
    redacted = session.redact(TEXT)
    for original in (EMAIL, SID, IPV4, IPV6, GUID, HOST, SECRET, "NORTHWIND", "ada.example"):
        assert original not in redacted
    assert session.reveal(redacted) == TEXT
    assert redacted.startswith("user LS_EMAIL_")
    assert "password=LS_SECRET_" in redacted


def test_case_variants_share_a_token():
    session = Session()
    first = session.redact(HOST)
    second = session.redact("Laptop-07.Northwind.Example")
    assert first == second
    assert session.reveal(second) == HOST


def test_user_path_keeps_profile_folders():
    redacted = Session().redact(r"C:\Users\ada.example\AppData\Local\Temp\FictionalInventory.cab")
    assert "ada.example" not in redacted
    assert r"AppData\Local" in redacted
    assert redacted.startswith("C:\\Users\\LS_USER_")


def test_leaves_filenames_build_numbers_and_clock_times():
    session = Session()
    assert session.redact("see AppEnforce.log for details") == "see AppEnforce.log for details"
    assert session.redact("see collector.jsonl for details") == "see collector.jsonl for details"
    assert "logsieve-vault.json.key" in session.redact("key file logsieve-vault.json.key")
    assert "10.0.22621.3527" in session.redact("build 10.0.22621.3527")
    assert "08:02:11" in session.redact("clock 08:02:11 still local")
    redacted = session.redact("address 1.2.3.4")
    assert "1.2.3.4" not in redacted
    assert "LS_IPV4_" in redacted


def test_guid_switch_and_secret_prefix():
    shown = Session(options=RedactOptions(guids=False)).redact(f"id {GUID}")
    assert GUID in shown
    hidden = Session().redact(f"id {GUID}")
    assert GUID not in hidden
    redacted = Session().redact(f"password={SECRET}")
    assert redacted.startswith("password=")
    assert SECRET not in redacted


def test_find_leaks_and_common_words():
    session = Session()
    session.redact(EMAIL)
    session.redact(HOST)
    session.redact("wsus.northwind.example")
    assert find_leaks(f"still here {EMAIL}", session.mapping)
    assert find_leaks("the short name laptop-07 remains", session.mapping)
    assert find_leaks("for example, see the report", session.mapping) == []
    assert find_leaks("WSUS is a product word", session.mapping) == []
    assert find_leaks("wsus.northwind.example leaked", session.mapping)


def test_vault_hides_plaintext_and_rejects_wrong_passphrase(tmp_path: Path):
    session = Session()
    session.redact(EMAIL)
    path = tmp_path / "vault.json"
    save_mapping(session.mapping, path, passphrase="correct horse", iterations=1000)
    blob = path.read_bytes()
    assert EMAIL.encode() not in blob
    restored = load_mapping(path, passphrase="correct horse")
    assert restored.reveal(session.redact(EMAIL)) == EMAIL
    with pytest.raises(LogsieveError, match="could not decrypt"):
        load_mapping(path, passphrase="nope")


def test_keyfile_mode(tmp_path: Path):
    mapping = Mapping()
    mapping.token("HOST", "laptop-07.northwind.example", HOST)
    path = tmp_path / "vault.json"
    key = tmp_path / "vault.json.key"
    save_mapping(mapping, path, key_path=key)
    assert HOST.encode() not in path.read_bytes()
    if os.name == "posix":
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert load_mapping(path, key_path=key).reveal(mapping.token("HOST", HOST, HOST)) == HOST