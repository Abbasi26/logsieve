# Roadmap

logsieve stays local-first: it reads logs, it does not change the endpoint, and nothing leaves the machine unless `--llm` is set.

## 0.2 (this branch)

- `logsieve explain` looks up a code, constant, pattern id, or pasted log line offline and prints the meaning, the checks, and the public sources. It also decodes the code (hex, signed, unsigned, HRESULT facility).
- `logsieve patterns --check` validates custom pattern YAML (loading, id collisions, https sources, self-test lines). CI runs it on the built-in library.
- `--format json|all` writes a machine-readable `report.json` from the same redacted fields, under the same leak check.

## Next

- More codes with public sources: BITS, Delivery Optimization, Autopilot ESP, MDM enrollment (`0x80180xxx`).
- `logsieve diagnose --since/--until` to cut a long log to an incident window.
- A SARIF or JUnit output so a CI or ticket system can attach findings.
- Tail of a growing log (opt-in, read-only).
- A memory-hard key derivation for the passphrase path (scrypt or Argon2) behind a vault format version.

## Good first issues

Each of these is small, self-contained, and covered by existing tests that show the shape.

1. **Add one error code.** Pick a code from a public Microsoft page, add it to the matching YAML in `src/logsieve/patterns/library/`, give it a fictional `self_test` line, and run `logsieve patterns --check`. Use the "New error code or pattern" issue form to claim it.
2. **`explain --open`**: print only the first source URL so it can be piped to a browser.
3. **Facility names**: extend `FACILITY_NAMES` in `src/logsieve/explain.py` with documented HRESULT facilities (with a source link in the comment).
4. **`patterns --area intune`**: filter the list by `area`.
5. **Timeline limit flag**: make the 200-event cap in the reports a `--timeline-limit` option.
6. **Docs**: a short walkthrough for collecting `C:\Windows\CCM\Logs` and the IME logs into one folder before `diagnose`.

Out of scope: a GUI, any action that changes the endpoint, sending raw logs to a hosted service.
