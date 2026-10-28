# Changelog

## 0.2.0 - 2026-10-28

- `logsieve explain CODE|LINE`: offline lookup in the pattern library by hex (`0x8024402C`, `8024402C`), signed or unsigned decimal, constant name, pattern id, event id, or a pasted log line. Shows the hex/signed/unsigned forms and the HRESULT facility, the explanation, checks, sources, and the uncertain flag. For a Win32 HRESULT (`0x8007xxxx`) it also tries the bare Win32 code. `--json` for scripts. Exit 1 when nothing matches.
- `logsieve patterns --check [PATH ...]`: validates pattern YAML. Reports load errors, ids that collide with each other or the built-in library, non-https sources, empty explanations, and missing or failing `self_test` lines. Exit 1 on a problem. CI runs it on the built-in library.
- `logsieve patterns --json` lists the library as JSON.
- `diagnose --format json` and `--format all`: `report.json` (schema 1) with the suspected cause, findings, next steps, and the redacted error timeline. An output path ending in `.json` selects it. JSON goes through the same identifier leak check as Markdown and HTML.
- ROADMAP.md with good first issues, issue forms (bug, feature, new error code), and a pull request template.

## 0.1.0 - 2026-10-21

First release.

- Parsers for CMTrace (including Intune Management Extension and AgentExecutor logs), Windows EVTX, exported event XML, event CSV, journald JSON, and plain text. Events land on one timeline.
- Reversible pseudonymization of hostnames, email and UPN, SIDs, IPv4, IPv6, GUIDs, domain names, and user-profile paths. Tokens stay stable for a run. The mapping is an encrypted local file. `logsieve reveal` puts the identifiers back.
- A YAML library of MECM, Intune, Windows Update, and Win32 codes with public sources. Uncertain entries are marked.
- `logsieve diagnose` writes a Markdown and HTML report: error timeline, matched patterns, a suspected cause, and checks. It does not change the machine.
- An optional OpenAI-compatible model call, off unless `--llm` is set. The payload is the redacted diagnosis. `--show-payload` prints that JSON and does not open a socket.
- `logsieve demo` runs on bundled fictional logs with no network.