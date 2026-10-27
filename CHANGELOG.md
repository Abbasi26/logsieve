# Changelog

## 0.1.0 - 2026-10-21

First release.

- Parsers for CMTrace (including Intune Management Extension and AgentExecutor logs), Windows EVTX, exported event XML, event CSV, journald JSON, and plain text. Events land on one timeline.
- Reversible pseudonymization of hostnames, email and UPN, SIDs, IPv4, IPv6, GUIDs, domain names, and user-profile paths. Tokens stay stable for a run. The mapping is an encrypted local file. `logsieve reveal` puts the identifiers back.
- A YAML library of MECM, Intune, Windows Update, and Win32 codes with public sources. Uncertain entries are marked.
- `logsieve diagnose` writes a Markdown and HTML report: error timeline, matched patterns, a suspected cause, and checks. It does not change the machine.
- An optional OpenAI-compatible model call, off unless `--llm` is set. The payload is the redacted diagnosis. `--show-payload` prints that JSON and does not open a socket.
- `logsieve demo` runs on bundled fictional logs with no network.