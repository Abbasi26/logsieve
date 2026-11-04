# Design decisions

## 2026-11-03: Time Window `--since` / `--until` for `logsieve diagnose`

[Specification](2026-11-03-zeitfenster-since-und-until.md)

- **Equal bounds (`--until == --since`) are an error (exit 2)**, not a valid empty window. The implementation (`until <= since`) and Error Behavior table (`≤`) already enforced this; the Risks table and Acceptance Criterion 5 were updated to match.
- **Invalid ISO-8601 input must produce exit 2** via `LogsieveError`, not a raw `ValueError` traceback (exit 1). The `_parse_utc_iso` helper wraps `datetime.fromisoformat` in a `try/except` raising `LogsieveError(code=2)`.
- **Parsing via `_parse_utc_iso`**: The helper handles `Z` → `+00:00`, naive timestamps as UTC, and offset conversion to UTC. It does not delegate to `plain.py:_parse_iso`.
- **Test plan fixed for executability**: `reversed_bounds_error` case now calls `main([...])` (CLI path) instead of `execute()` directly; event-factory helper signature added to satisfy Zero-Decision Rule; boundary rows split to independently exercise inclusive lower and exclusive upper bounds; all test timestamps prefixed with a fixed date (`2026-10-21T...`).
- **Acceptance Criterion #2 made testable**: Added assertion on `outcome.diagnosis.primary` / `findings` to verify out-of-window pattern codes are not reported.
- **No `Report.time_window` field**: The report does not carry a time_window audit trail; the warning counts only timestamp-less events dropped, not bound-dropped events.
- **Filter uses in-place modification** to avoid doubling peak memory on large logs.
- **Implementation plan phased**: Split into four phases (CLI args + parsing, pipeline filter + warning, tests, docs) with verification checkpoints, each leaving the codebase buildable and testable.
- **CHANGELOG instruction corrected**: "Add under `## Unreleased` (create if missing)" — the file has no `## Next` section.
- **README placement clarified**: "Add to the top-level 'Useful flags:' list" — no `diagnose` subsection exists.
- **Naive-timestamp caveat preserved in docs**: README bullet and CHANGELOG entry include "until a future spec addresses this" to match the Risk mitigation.
- **Contested (out of scope for Detailed Implementation Plan)**: Spec 5.3 existence, ROADMAP linking, Problem Statement phrasing, synonym drift, Risks table security/scalability rows — these belong to the Feature section (lines 1–71) and were not changed in this resolution pass.