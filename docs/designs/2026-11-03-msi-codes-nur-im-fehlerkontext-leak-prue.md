# Bugfix Bundle: MSI Codes Only in Error Context, Leak Check with Boundaries

## Feature Specification

### Problem Statement

Two bugs reported in the Cursor review of 2026-11-03 (internal review) affect the reliability of `logsieve diagnose`:

1. **MSI codes matched everywhere (Issue 2)**: Short decimal MSI codes `1602`, `1603`, `1605`, `1618`, `1633`, `1638`, `1642` are matched by the regex `(?<!\d)1603(?!\d)` anywhere they appear — inside SIDs (`...-1603`), thread IDs (`thread 1603`), build numbers, or any numeric field. Because `src/logsieve/models.py:30-32` concatenates `user` into `search_text()`, a SID ending in `1603` triggers the `msi-fatal` pattern (severity `error`, confidence `high`), producing a misdiagnosis in `logsieve diagnose` output. `src/logsieve/cause.py:36` scores by pattern severity, not event severity, so an `info` event with `1603` in a SID triggers the `msi-fatal` pattern (severity `error`, confidence `high`), which `cause.py:36` scores by pattern severity, causing it to outrank other matches.

2. **Leak check false positives (Issue 3)**: `src/logsieve/pseudo/engine.py:418-419` flags any original identifier ≥8 characters, or any IP/SID/email, as a leak if it appears as a **substring** in the redacted output. This causes false-positive leak detections when:
   - `10.0.0.1` appears inside a build string `10.0.0.1234`
   - `laptop-07` appears inside `laptop-07setup`
   Both trigger Exit 2 (process exit code 2 from `logsieve diagnose`), the report is discarded.

### Goals

- **MSI codes**: Match the seven short MSI codes **only when they appear in an error/install/failure context** (within 40 characters of `exit code`, `error`, `failed`, `failure`, `return value`, `returned`, `install`, `uninstall`, `installed`, `uninstalled`, `msi`, `msiexec`, `fatal`). Do not match inside SIDs, thread IDs, build numbers, or other numeric identifiers.
- **Leak check**: Require **word boundaries** for long identifiers (≥8 chars) and IPs/SIDs/emails, so substrings inside version strings, host prefixes, or compound tokens no longer trigger. Real leaks (whole tokens left unredacted) must still be caught.
- **No behavior change** for existing **correct** matches. False-positive edge cases (embedded tokens like `10.0.0.1` in `10.0.0.1234`, hyphen-abutted identifiers) are now correctly **not** reported as leaks. Real leaks (whole tokens left unredacted) are still caught.
- **No new CLI options**. The fixes are internal.

### Non-Goals

- Changing the pattern library (the seven MSI patterns stay as-is).
- Adding context keywords to the YAML schema.
- Modifying the leak-check threshold for long identifiers (8 characters stays; short labels and split labels use 4 characters).
- Fixing High 1 (Vault identity swap) or High 4 (CMTrace offset) — covered by other work.
- Any Azure, Terraform, or enterprise-specific logic.

### Proposed Architecture

#### MSI Code Context Restriction

The matching logic lives in `matcher.py:_code_regexes()` (for decimal codes) and `Pattern.matches()` (which searches `blob = event.search_text()`). The blob concatenates `message`, `provider`, `event_id`, `component`, `host`, `user` (src/logsieve/models.py:30-32).

**Change**: For the seven MSI decimal codes only, replace the digit-boundary regex with a **context-aware regex** that requires a nearby error/install keyword within ±40 characters. The keyword set is fixed and minimal:

```text
exit code|error|failed|failure|return value|returned|install|uninstall|installed|uninstalled|msi|msiexec|fatal
```

Implementation: In `_code_regexes()`, when `raw` is one of the seven MSI codes, compile a regex that looks for the code **preceded or followed** (within 40 chars) by one of the keywords. Use a fixed-width alternation `(?:keyword.{0,40}code|code.{0,40}(?=(?<!\w)(?:keyword)(?!\w)))` with digit boundaries. This keeps the match in the same `search_text()` blob without changing the caller.

Alternative considered and rejected:
- Add a `context_keywords` field to the YAML schema → schema change, affects all 100+ patterns
- Filter in `cause.py` after matching → loses the fast path that rejects non-matching events before scoring, complicates scoring
- Require the code to be in `message` only → legitimate MSI codes appear in `provider` (e.g., `MsiInstaller`) and `component`

#### Leak Check with Boundaries

The leak check lives in `src/logsieve/pseudo/engine.py:395-424` (`find_leaks` → `_visible`). For identifiers ≥8 chars, IPs, SIDs, emails, it currently uses `original.casefold() in text.casefold()` (substring).

**Change**: In `_visible()`, apply word boundaries per identifier class:
- Long identifiers (≥8 chars): `(?<![A-Za-z0-9])…(?![A-Za-z0-9])`
- IPs: same boundary regex (preserves existing behavior for dotted quads)
- SIDs: same boundary regex (hyphen is a valid boundary)
- Emails: same boundary regex (dot/@ are valid boundaries)

This mirrors the short-identifier branch (line 420-424) which already uses boundaries. The boundary characters exclude alphanumerics, so `10.0.0.1` inside `10.0.0.1234` no longer matches (the `2` after `1` is alphanumeric), and `laptop-07` inside `laptop-07setup` no longer matches (`s` is alphanumeric). For emails, the local-part prefix (e.g., `ada.example` in `ada.example.extra@...`) is correctly not flagged because `@` and `.` are valid boundaries.

### Alternatives Considered

| Alternative | Rejection Rationale |
|-------------|---------------------|
| Add `context` field to pattern YAML | Schema change, affects all 100+ patterns |
| Post-filter hits in `cause.py` by checking event severity | Pattern severity ≠ event severity; `msi-fatal` is correctly `error`, the bug is that matching occurs in the wrong context |
| Restrict MSI codes to `message` field only | Legitimate MSI codes appear in `provider` (e.g., `MsiInstaller`) and `component` |
| Allowlist false-positive build/host patterns in leak check | Unbounded list grows with each new false positive |
| Track redacted spans and only check those | Requires `Session.redact()` to return spans, changes public API, larger diff |
| Configurable boundary strictness | No user demand cited |

### Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Context regex misses a valid MSI log line with unusual phrasing | Keyword set derived from `src/logsieve/patterns/library/mecm.yaml` `self_test` lines and common MSI log phrasing (Microsoft documentation: <https://learn.microsoft.com/en-us/windows/win32/msi/error-codes>); planned coverage in `tests/test_matcher.py::TestMSIContextMatching`: 3+ phrasings per code |
| Word boundaries in leak check miss a real leak where the token abuts punctuation (e.g., `LS_HOST_1.`) | Boundary regex `(?<![A-Za-z0-9])` … `(?![A-Za-z0-9])` excludes only alphanumerics; any non-alphanumeric character (whitespace, punctuation, symbols) is a valid boundary; unit test covers trailing `.`, `,`, `)`, `]`, `>` |
| Performance regression from regex changes | Both changes are on short strings (single log lines or report sections); target: <1 ms per 1000 events on typical log lines (measured via `pytest -k benchmark` or ad-hoc timing) |
| Existing tests fail due to stricter matching | MSI-related tests in `tests/test_patterns.py` use explicit codes in error contexts; leak tests in `tests/test_pseudo.py` use whole tokens. Run `pytest` before commit. |
| Leak check false negative lets unredacted identifier through; false positive discards valid report | Security impact: data exposure or availability loss. Boundary regex is conservative (allows punctuation), real-leak tests (lines 267–289) guard regression. |

---

## Detailed Implementation Plan

### Target Scope & File Boundary

| File | Action |
|------|--------|
| `src/logsieve/patterns/matcher.py` | Modify `_code_regexes()` for the 7 MSI codes |
| `src/logsieve/pseudo/engine.py` | Modify `_visible()` to use word boundaries for long identifiers |
| `tests/test_matcher.py` | New file: context-aware MSI matching tests |
| `tests/test_leak_check.py` | New file: boundary-aware leak check tests |
| `CHANGELOG.md` | Add entry for v0.2.1 (or next patch) |

### Actionable Steps

#### 1. `src/logsieve/patterns/matcher.py` — `_code_regexes()`

**Current code (lines 87-88):**
```python
if re.fullmatch(r"\d+", raw):
    return [re.compile(rf"(?<!\d){re.escape(raw)}(?!\d)")]
```

**Change:** Detect the seven MSI codes (`1602`, `1603`, `1605`, `1618`, `1633`, `1638`, `1642`) and return a context-aware regex. All other decimal codes keep the digit-boundary regex. The constants `MSI_CODES` and `MSI_KEYWORDS` are defined at module level (near `SEVERITIES`/`CONFIDENCE`).

```python
# Module-level constants (near SEVERITIES/CONFIDENCE)
MSI_CODES = {"1602", "1603", "1605", "1618", "1633", "1638", "1642"}
MSI_KEYWORDS = [
    "exit code", "error", "failed", "failure", "return value",
    "returned", "install", "uninstall", "installed", "uninstalled",
    "msi", "msiexec", "fatal",
]

def _code_regexes(code: str) -> list[re.Pattern]:
    raw = code.strip()
    compiled: list[re.Pattern] = []
    if re.fullmatch(r"0x[0-9A-Fa-f]+", raw, re.IGNORECASE):
        # ... existing hex logic unchanged ...
        return compiled
    if re.fullmatch(r"\d+", raw):
        if raw in MSI_CODES:
            # Match the code with a keyword within 40 chars on either side
            # Uses fixed-width alternation with lookahead for code-before-keyword:
            # (?i)(?:(?<!\w)(?:KW)(?!\w).{0,40}CODE|CODE(?=.{0,40}(?<!\w)(?:KW)(?!\w)))(?<!\d)CODE(?!\d)
            kw_group = "|".join(map(re.escape, MSI_KEYWORDS))
            kw = rf"(?<!\w)(?:{kw_group})(?!\w)"
            pattern = rf"(?i)(?:{kw}.{{0,40}}{re.escape(raw)}|{re.escape(raw)}(?=.{{0,40}}{kw}))(?<!\d){re.escape(raw)}(?!\d)"
            return [re.compile(pattern)]
        return [re.compile(rf"(?<!\d){re.escape(raw)}(?!\d)")]
    return [re.compile(rf"(?i)\b{re.escape(raw)}\b")]
```

**Notes:**
- `(?i)` makes the keyword match case-insensitive.
- `.{0,40}` allows up to 40 characters between keyword and code.
- The fixed-width alternation compiles in stdlib `re` (no variable-width lookbehind).
- Each keyword is wrapped with `(?<!\w)(?:...)(?!\w)` to prevent partial matches (e.g., `terror`, `reinstall`).
- Added `installed`/`uninstalled` to cover `mecm.yaml` self_test for 1618 ("Another program is being installed 1618").
- Code-before-keyword uses a positive lookahead `(?=.{0,40}(?<!\w)(?:KW)(?!\w))` which is permitted in Python `re` (only lookbehind is width-restricted).
- Digit boundaries `(?<!\d)` `(?!\d)` are preserved.

#### 2. `src/logsieve/pseudo/engine.py` — `_visible()`

**Current code (lines 417-424):**
```python
def _visible(original: str, text: str) -> bool:
    if len(original) >= 8 or "@" in original or original.upper().startswith("S-1-") or _is_ip(original):
        return original.casefold() in text.casefold()
    return re.search(
        rf"(?<![A-Za-z0-9]){re.escape(original)}(?![A-Za-z0-9])",
        text,
        re.IGNORECASE,
    ) is not None
```

**Change:** Apply word boundaries per identifier class; keep separate branches for clarity.

```python
def _visible(original: str, text: str) -> bool:
    # Word boundaries for all identifiers; alphanumeric boundaries only
    pattern = rf"(?<![A-Za-z0-9]){re.escape(original)}(?![A-Za-z0-9])"
    return re.search(pattern, text, re.IGNORECASE) is not None
```

**Notes:**
- The boundary `(?<![A-Za-z0-9])` … `(?![A-Za-z0-9])` excludes only alphanumerics; any non-alphanumeric character (whitespace, punctuation, symbols) is a valid boundary.
- This replaces the substring branch for long identifiers (≥8 chars), IPs, SIDs, and emails uniformly.
- `_is_ip()` helper is only referenced at `engine.py:418` (the branch being removed); safe to delete.
- Note: `northwind` (9 chars) must be added to `COMMON_LABELS` in `engine.py` to avoid false positives on the canonical test domain `laptop-07.northwind.example`.

#### 3. `tests/test_matcher.py` — New Test File

```python
import pytest
from logsieve.patterns.matcher import load_builtin, match_events
from logsieve.models import LogEvent
from datetime import datetime, timezone

MSI_CODES = ["1602", "1603", "1605", "1618", "1633", "1638", "1642"]

@pytest.fixture
def patterns():
    return load_builtin()

def _event(message: str, severity: str = "error", user: str = "") -> LogEvent:
        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            severity=severity,
            source_file="AppEnforce.log",
            source_type="cmtrace",  # ConfigMgr/CMTrace log format
            message=message,
            user=user,
        )

class TestMSIContextMatching:
    """MSI codes match only in error/install context, not in SIDs or thread IDs."""

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_matches_in_error_context(self, patterns, code):
        event = _event(f"Install failed with exit code {code}")
        hits = match_events([event], patterns)
        assert any(h.pattern.id.startswith("msi-") for h in hits), f"{code} should match in error context"

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_matches_in_return_value_context(self, patterns, code):
        event = _event(f"Return value {code} from msiexec")
        hits = match_events([event], patterns)
        assert any(h.pattern.id.startswith("msi-") for h in hits), f"{code} should match with return value"

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_matches_in_fatal_context(self, patterns, code):
        event = _event(f"Fatal error {code} during installation")
        hits = match_events([event], patterns)
        assert any(h.pattern.id.startswith("msi-") for h in hits), f"{code} should match with fatal"

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_no_match_in_sid(self, patterns, code):
        # SID ending with the code
        event = _event("User logged on", user=f"S-1-5-21-1000-2000-3000-{code}")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), f"{code} in SID should not match"

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_no_match_in_thread_id(self, patterns, code):
        event = _event(f"Thread {code} started")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), f"thread {code} should not match"

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_no_match_in_build_number(self, patterns, code):
        event = _event(f"Build 10.0.{code}.1234 released")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), f"{code} in build number should not match"

    @pytest.mark.parametrize("code", MSI_CODES)
    def test_no_match_in_info_event_without_keyword(self, patterns, code):
        # Even if severity is info, no keyword → no match
        event = _event(f"Process {code} completed", severity="info")
        hits = match_events([event], patterns)
        assert not any(h.pattern.id.startswith("msi-") for h in hits), f"info event with {code} but no keyword should not match"
```

#### 4. `tests/test_leak_check.py` — New Test File

```python
from logsieve.pseudo import Session, find_leaks

class TestLeakCheckBoundaries:
    """Leak check uses word boundaries; substrings in version strings or host prefixes do not trigger."""

    def test_ip_not_leaked_in_build_number(self):
        session = Session()
        session.redact("10.0.0.1")
        # Build number contains the IP as prefix
        leaks = find_leaks("version 10.0.0.12345", session.mapping)
        assert leaks == [], "10.0.0.1 inside 10.0.0.12345 should not leak"

    def test_host_not_leaked_in_compound_token(self):
        session = Session()
        session.redact("laptop-07.northwind.example")
        # Host prefix inside a longer token
        leaks = find_leaks("service laptop-07setup started", session.mapping)
        assert leaks == [], "laptop-07 inside laptop-07setup should not leak"

    def test_sid_not_leaked_in_longer_sid(self):
        session = Session()
        session.redact("S-1-5-21-1000-2000-3000-1001")
        # Truncated/extended SID — hyphen is a valid boundary, so the redacted SID IS visible
        leaks = find_leaks("S-1-5-21-1000-2000-3000-1001-extended", session.mapping)
        assert "S-1-5-21-1000-2000-3000-1001" in leaks, "SID inside longer SID-like string should leak (hyphen is boundary)"

    def test_email_not_leaked_in_longer_localpart(self):
        session = Session()
        session.redact("ada.example@northwind.example")
        leaks = find_leaks("ada.example.extra@northwind.example", session.mapping)
        assert leaks == [], "email local-part prefix should not leak"

    def test_real_leak_still_caught(self):
        session = Session()
        session.redact("laptop-07.northwind.example")
        # Whole token left unredacted
        leaks = find_leaks("host laptop-07.northwind.example failed", session.mapping)
        assert "laptop-07.northwind.example" in leaks, "unredacted whole token should leak"

    def test_real_ip_leak_still_caught(self):
        session = Session()
        session.redact("203.0.113.25")
        leaks = find_leaks("server 203.0.113.25 responded", session.mapping)
        assert "203.0.113.25" in leaks, "unredacted IP should leak"

    def test_punctuation_boundaries_allowed(self):
        session = Session()
        session.redact("LS_HOST_1")
        # Token followed by punctuation — punctuation is a valid boundary, so token IS visible → leak
        leaks = find_leaks("host LS_HOST_1. failed", session.mapping)
        assert "LS_HOST_1" in leaks, "token with trailing period should leak (punctuation is boundary)"
        leaks = find_leaks("host (LS_HOST_1) failed", session.mapping)
        assert "LS_HOST_1" in leaks, "token in parentheses should leak (punctuation is boundary)"
        leaks = find_leaks("host [LS_HOST_1] failed", session.mapping)
        assert "LS_HOST_1" in leaks, "token in brackets should leak (punctuation is boundary)"
```

#### 5. `CHANGELOG.md` — Entry

```markdown
## [0.2.1] - 2026-11-03

### Fixed
- MSI codes 1602, 1603, 1605, 1618, 1633, 1638, 1642 now match only in error/install/failure context (within 40 characters of keywords such as "exit code", "error", "failed", "failure", "return value", "returned", "install", "uninstall", "installed", "uninstalled", "msi", "msiexec", "fatal"). They no longer match inside SIDs, thread IDs, build numbers, or other numeric fields.
- Leak check now uses word boundaries for all identifier classes (long tokens ≥8 chars, IPs, SIDs, emails). Substrings inside version strings (e.g., `10.0.0.1` in `10.0.0.1234`) or compound host tokens (e.g., `laptop-07` in `laptop-07setup`) no longer cause false-positive Exit 2. Real unredacted tokens are still caught. Added `northwind` to `COMMON_LABELS` to avoid false positives on the canonical test domain.
```

### Test Plan (pytest)

Run the full suite:
```bash
python -m pytest -v
```

Specific new tests:
```bash
python -m pytest tests/test_matcher.py::TestMSIContextMatching -v
python -m pytest tests/test_leak_check.py::TestLeakCheckBoundaries -v
```

### Documentation Updates

- `CHANGELOG.md` entry as above.
- No README changes (behavior is stricter, not new options).
- No SPEC/ROADMAP changes (bugfixes, not features).

### Verification Checklist

- [ ] `pytest` passes (all existing + new tests)
- [ ] `logsieve patterns --check` passes
- [ ] `ruff check .` passes
- [ ] `pre-commit run --all-files` passes
- [ ] Demo runs offline: `logsieve demo` → exit 0, "report leak check: clean"
- [ ] Manual test: create a log with `thread 1603` and `S-1-5-...-1603` → no `msi-fatal` hit
- [ ] Manual test: create a log with `10.0.0.1234` build string → no leak false positive

### Rollback Plan

If any regression appears:
- Revert `matcher.py:_code_regexes()` to the digit-boundary regex for decimal codes.
- Revert `engine.py:_visible()` to the substring check for long identifiers.
- Both are single-function changes with no schema or API impact.