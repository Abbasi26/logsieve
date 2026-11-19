# Time Window `--since` / `--until` — Feature Specification

## Problem Statement

Diagnosing a Windows endpoint often involves logs that span days or weeks, but the relevant incident occurs within a narrow time window. Without a way to restrict analysis to that window, `logsieve diagnose` processes the entire log corpus, producing a timeline, pattern matches, and suspected cause that include unrelated events. This dilutes the signal, increases processing time, and makes reports harder to read.

## Goals & Non-Goals

### Goals
- Add `--since` and `--until` flags to `logsieve diagnose` to filter events by timestamp.
- Both flags accept ISO-8601 timestamps in UTC (e.g., `2026-10-21T08:00:00Z` or `2026-10-21T08:00:00+00:00`).
- `--since` is inclusive; `--until` is exclusive.
- Filtering happens after parsing and before pattern matching (`match_events`), so only events inside the window contribute to the timeline, pattern hits, and suspected cause.
- Events without a timestamp are excluded when a window is set; a warning reports how many were dropped.
- Without either flag, behavior is identical to today (no filtering).
- `--until` before `--since` is an argument error with exit code 2.
- Naive timestamps (no timezone) are treated as UTC until a future spec addresses this.

### Non-Goals
- Timezone conversion or local-time input (deferred to Spec 5.3).
- Filtering by relative durations (e.g., `--last 1h`).
- Windowing for `explain`, `patterns`, `reveal`, or `demo` commands.
- Streaming/tail support (out of scope per ROADMAP).

## Proposed Architecture

The change is confined to the `diagnose` command path:

1. **CLI Layer** (`src/logsieve/cli.py`): Add two optional arguments `--since` and `--until` to the `diagnose` subparser. Parse them into timezone-aware `datetime` objects (UTC). Validate ordering (`until <= since` → error).

2. **Pipeline Layer** (`src/logsieve/pipeline.py`): Extend `execute()` to accept `since` and `until` parameters. After `collect_events()` returns the full sorted event list, apply a filter step before `match_events()`. Count events without timestamps that are dropped; emit a warning.

3. **Event Model** (`src/logsieve/models.py`): No changes. `LogEvent.timestamp` remains `datetime | None`.

4. **Tests** (`tests/test_timeline_precision.py`): Add parametrized tests covering inclusive/exclusive boundaries, mixed timestamp presence, missing flags, and reversed bounds.

5. **Documentation**: Update `README.md` (flag descriptions) and `CHANGELOG.md` (release entry).

Data flow remains linear: parse → sort → **filter by window** → match → redact → rank → render.

## Alternatives Considered

| Alternative | Rejection Rationale |
|-------------|---------------------|
| Filter during parsing (inside each parser) | Parsers are format-specific; window logic is cross-cutting. Centralizing in `execute()` avoids duplicating filter code across 6+ parsers. |
| Relative time syntax (`--last 2h`) | Adds parsing complexity and ambiguity (relative to now? to file mtime?). ISO-8601 is unambiguous and scriptable. Deferred to a follow-up if users request it. |
| Separate `filter` subcommand | Would require piping JSON between commands, complicating the vault/mapping workflow. A single `diagnose` run is simpler and preserves reversible pseudonymization. |
| Timezone-aware input with IANA zones | Scope creep. Spec 5.3 will address naive vs. aware handling; this spec explicitly treats naive as UTC. |
| Filter after `match_events` | Would waste CPU matching patterns on events that are discarded. Filtering before matching is strictly more efficient. |

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Users pass naive timestamps assuming local time | Help text and README state "naive timestamps are treated as UTC until Spec 5.3". |
| Large logs with many timestamp-less events produce noisy warnings | Warning reports a count only; does not spam per-event. |
| `--until` equal to `--since` yields empty window (valid but possibly unintended) | Treated as an error (exit 2): `--until must be after --since` |
| Existing tests break due to new parameters | All new parameters have defaults (`None`); existing call sites (demo, tests) work unchanged. |

## Acceptance Criteria

1. Events at 07:00, 08:30, 10:00 UTC; window `--since 2026-10-21T08:00:00Z --until 2026-10-21T09:00:00Z` → only 08:30 remains.
2. A pattern code that appears only in the 07:00 or 10:00 event is not reported as a hit or cause.
3. An event without a timestamp appears in the warning count and not in the timeline.
4. Running without `--since`/`--until` shows all three events.
5. `--until` before `--since` exits with code 2 and a clear error message.
6. Inclusive lower bound: event exactly at `--since` is kept.
7. Exclusive upper bound: event exactly at `--until` is dropped.

---

## Detailed Implementation Plan

### Target Scope & File Boundary

| File | Change Type |
|------|-------------|
| `src/logsieve/cli.py` | Modify |
| `src/logsieve/pipeline.py` | Modify |
| `tests/test_timeline_precision.py` | Modify |
| `README.md` | Modify |
| `CHANGELOG.md` | Modify |

No new files. No dependency additions.

### Actionable Steps

#### 1. `src/logsieve/cli.py`

**A. Add arguments to `diagnose` subparser (after `--pattern-dir`):**
```python
diagnose.add_argument(
    "--since",
    type=str,
    help="Include events at or after this ISO-8601 UTC timestamp (inclusive). Naive timestamps are treated as UTC.",
)
diagnose.add_argument(
    "--until",
    type=str,
    help="Exclude events at or after this ISO-8601 UTC timestamp (exclusive). Naive timestamps are treated as UTC.",
)
```

**B. Parse and validate in `_diagnose()`:**
```python
from datetime import datetime, timezone

def _parse_utc_iso(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LogsieveError(f"invalid timestamp '{value}': {exc}", code=2) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt

def _diagnose(args: argparse.Namespace) -> int:
    since = _parse_utc_iso(args.since) if args.since else None
    until = _parse_utc_iso(args.until) if args.until else None
    if since and until and until <= since:
        raise LogsieveError("--until must be after --since", code=2)
    # ... pass since, until to execute()
```

**C. Pass to `execute()`:** Add `since=since, until=until` to the `execute()` call.

#### 2. `src/logsieve/pipeline.py`

**A. Update `execute()` signature:**
```python
def execute(
    paths: list[Path],
    *,
    parser: str = "auto",
    options: RedactOptions | None = None,
    pattern_dirs: list[Path] | None = None,
    vault: Path | None = None,
    vault_key: Path | None = None,
    passphrase: str | None = None,
    iterations: int = DEFAULT_ITERATIONS,
    output: Path | None = None,
    fmt: str = "md",
    llm_url: str | None = None,
    llm_model: str = "llama3.2",
    llm_timeout: float = 60,
    llm_api_key: str | None = None,
    show_payload: bool = False,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Outcome:
```

**B. Add filter step after `collect_events()` and before `match_events()`:**
```python
    events, warnings = collect_events(paths, parser)

    # Time window filter
    if since is not None or until is not None:
        filtered: list[LogEvent] = []
        no_timestamp_dropped = 0
        for event in events:
            ts = event.timestamp
            if ts is None:
                no_timestamp_dropped += 1
                continue
            # Normalize to UTC for comparison
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            else:
                ts = ts.astimezone(timezone.utc)
            if since is not None and ts < since:
                continue
            if until is not None and ts >= until:
                continue
            filtered.append(event)
        if no_timestamp_dropped:
            warnings.append(f"time window: {no_timestamp_dropped} event(s) without a timestamp were excluded")
        events = filtered
```

**C. No other changes needed.** The rest of the pipeline (matching, redaction, ranking, rendering) operates on the filtered `events` list.

#### 3. `tests/test_timeline_precision.py`

Add a new test class `TestTimeWindow` with the following parametrized tests (using `pytest.mark.parametrize`):

| Test Case | Setup | Since | Until | Expected Kept | Expected Dropped (no ts) | Notes |
|-----------|-------|-------|-------|---------------|--------------------------|-------|
| `window_inclusive_lower` | events at 08:00, 08:30, 09:00 | 08:00 | 09:00 | 08:00, 08:30 | 0 | `--since` inclusive |
| `window_exclusive_upper` | events at 08:00, 08:30, 09:00 | 08:00 | 09:00 | 08:00, 08:30 | 0 | `--until` exclusive (09:00 dropped) |
| `window_mid_range` | events at 07:00, 08:30, 10:00 | 08:00 | 09:00 | 08:30 | 0 | Core acceptance case |
| `no_timestamp_dropped` | events at 08:30 + 1 no-ts | 08:00 | 09:00 | 08:30 | 1 | Warning emitted |
| `no_timestamp_no_window` | events at 08:30 + 1 no-ts | None | None | both | 0 | No window = no drop |
| `since_only` | events at 07:00, 08:30, 10:00 | 08:00 | None | 08:30, 10:00 | 0 | Open-ended upper |
| `until_only` | events at 07:00, 08:30, 10:00 | None | 09:00 | 07:00, 08:30 | 0 | Open-ended lower |
| `reversed_bounds_error` | any | 09:00 | 08:00 | — | — | Exit 2 from CLI |

Each test calls `execute()` directly (bypassing CLI) with `since`/`until` parameters, and asserts on `outcome.events`, `outcome.warnings`, and (for the error case) that `LogsieveError` with `code=2` is raised from the CLI path.

#### 4. `README.md`

Add to the "Useful flags" section under `diagnose`:

```markdown
- `--since TIMESTAMP` and `--until TIMESTAMP` (ISO-8601 UTC, e.g. `2026-10-21T08:00:00Z`) to restrict the timeline to an incident window. `--since` inclusive, `--until` exclusive. Events without a timestamp are excluded when a window is set; a warning reports the count. Naive timestamps are treated as UTC.
```

#### 5. `CHANGELOG.md`

Add under "## Next" (unreleased) or a new version header when released:

```markdown
- `diagnose --since/--until`: filter events to an ISO-8601 UTC time window (inclusive lower bound, exclusive upper bound). Events without timestamps are excluded with a warning. Naive timestamps are treated as UTC.
```

### Parameter/Signature Summary

| Function | New Parameters |
|----------|----------------|
| `_diagnose()` (internal) | `since: datetime \| None`, `until: datetime \| None` |
| `execute()` | `since: datetime \| None = None`, `until: datetime \| None = None` |

### Error Behavior

| Condition | Exit Code | Message |
|-----------|-----------|---------|
| `--until` ≤ `--since` | 2 | `--until must be after --since` |
| Invalid ISO-8601 format | 2 | `logsieve: invalid timestamp '...': ...` (via `LogsieveError`) |

### Test Cases (pytest)

See the table in Step 3 above. All tests are offline, use temporary JSONL files, and assert on `outcome.events`, `outcome.warnings`, and exception codes.

### Documentation Changes

- `README.md`: One bullet in "Useful flags".
- `CHANGELOG.md`: One line in the unreleased/next section.

---

**Estimated Diff Scope**: < 300 lines changed across 5 files. No new dependencies. No architectural shifts.