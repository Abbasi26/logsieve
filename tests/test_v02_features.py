import json

from logsieve.cli import main
from logsieve.demo import DEMO_LOGS
from logsieve.explain import code_forms, explain
from logsieve.lint import lint_patterns
from logsieve.patterns import load_builtin
from logsieve.patterns.matcher import LIBRARY_DIR

GOOD = """
- id: contoso-agent-timeout
  title: Example agent timed out
  codes: ["0x8FFF0001"]
  severity: error
  confidence: low
  uncertain: true
  explanation: Fictional pattern for the lint test.
  sources: ["https://example.com/agent-timeout"]
  self_test: "agent returned 0x8FFF0001"
"""


def test_code_forms_reads_hex_signed_and_unsigned():
    forms = code_forms("0x8024402c")
    assert forms.hex == "0x8024402C"
    assert forms.signed == -2145107924
    assert forms.facility == 36 and forms.facility_name == "Windows Update"
    assert code_forms("-2145107924").hex == "0x8024402C"
    assert code_forms("2149859372").hex == "0x8024402C"
    assert code_forms("8024402C").hex == "0x8024402C"
    assert code_forms("not a code") is None
    win32 = code_forms("0x80072EE7")
    assert win32.facility == 7 and win32.code == 12007


def test_explain_finds_pattern_by_hex_decimal_id_and_log_line():
    patterns = load_builtin()
    for query in ("0x8024402C", "-2145107924", "wu-name-not-resolved", "WU_E_PT_WINHTTP_NAME_NOT_RESOLVED",
                  "Windows Update failed with error 0x8024402C while scanning"):
        ids = [pattern.id for pattern, _ in explain(query, patterns).matches]
        assert "wu-name-not-resolved" in ids, query


def test_explain_keeps_uncertain_flag():
    result = explain("-2016345060", load_builtin())
    match = result.as_dict()["matches"][0]
    assert match["id"] == "intune-not-detected"
    assert match["uncertain"] is True
    assert match["sources"] and all(item.startswith("https://") for item in match["sources"])


def test_explain_cli_text_json_and_miss(capsys):
    assert main(["explain", "0x8024402C"]) == 0
    out = capsys.readouterr().out
    assert "wu-name-not-resolved" in out and "learn.microsoft.com" in out
    assert main(["explain", "--json", "0x80072EE7"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["forms"]["facility_name"] == "Win32"
    assert data["matches"]
    assert main(["explain", "0xDEADBEEF"]) == 1
    assert "not in the library" in capsys.readouterr().out


def test_lint_builtin_library_is_clean():
    result = lint_patterns([LIBRARY_DIR])
    assert result.ok, result.problems
    assert result.patterns == len(load_builtin())


def test_lint_reports_each_problem(tmp_path):
    (tmp_path / "good.yaml").write_text(GOOD, encoding="utf-8")
    (tmp_path / "bad.yaml").write_text(
        """
- id: wu-name-not-resolved
  title: collides with the built-in id
  codes: ["0x8FFF0002"]
  sources: ["http://example.com/plain-http"]
  explanation: x
  self_test: "this line does not contain the code"
- id: no-self-test
  title: missing self test
  codes: ["0x8FFF0003"]
  sources: ["https://example.com/x"]
""",
        encoding="utf-8",
    )
    (tmp_path / "broken.yaml").write_text("- id: x\n  title: [unclosed\n", encoding="utf-8")
    result = lint_patterns([tmp_path])
    text = "\n".join(result.problems)
    assert "built-in library" in text
    assert "not an https URL" in text
    assert "self_test line does not match" in text
    assert "self_test is missing" in text
    assert "explanation is empty" in text
    assert "broken.yaml: does not load" in text
    assert "contoso-agent-timeout" not in text


def test_patterns_check_cli_exit_codes(tmp_path, capsys):
    (tmp_path / "good.yaml").write_text(GOOD, encoding="utf-8")
    assert main(["patterns", "--check", str(tmp_path)]) == 0
    assert main(["patterns", "--check"]) == 0
    (tmp_path / "bad.yaml").write_text(GOOD.replace("contoso-agent-timeout", "other").replace("0x8FFF0001\"]", "0x8FFF0009\"]"), encoding="utf-8")
    assert main(["patterns", "--check", str(tmp_path)]) == 1
    assert "does not match" in capsys.readouterr().out


def test_patterns_json_lists_library(capsys):
    assert main(["patterns", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == len(load_builtin())
    assert {"id", "match", "uncertain", "sources"} <= set(rows[0])


def test_diagnose_json_to_stdout_is_redacted(capsys):
    assert main(["diagnose", str(DEMO_LOGS), "--format", "json"]) == 0
    raw = capsys.readouterr().out
    data = json.loads(raw)
    assert data["schema"] == 1
    assert data["suspected_cause"]["id"] == "wu-name-not-resolved"
    assert data["errors"] == len(data["timeline"])
    assert "northwind.example" not in raw
    assert "LS_HOST_" in raw


def test_diagnose_all_writes_three_files(tmp_path):
    out = tmp_path / "out"
    assert main(["diagnose", str(DEMO_LOGS), "--format", "all", "--output", str(out)]) == 0
    assert sorted(path.name for path in out.iterdir()) == ["report.html", "report.json", "report.md"]
    single = tmp_path / "single.json"
    assert main(["diagnose", str(DEMO_LOGS), "--output", str(single)]) == 0
    assert json.loads(single.read_text(encoding="utf-8"))["tool"] == "logsieve"
