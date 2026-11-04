# Design decisions

## 2026-11-03: MSI Codes Only in Error Context, Leak Check with Boundaries

**Design:** [2026-11-03-msi-codes-nur-im-fehlerkontext-leak-prue.md](2026-11-03-msi-codes-nur-im-fehlerkontext-leak-prue.md)

### Decisions

1. **MSI context regex uses fixed-width alternation with lookahead for code-before-keyword** — Rejected variable-width lookbehind (non-compiling in stdlib `re`). Adopted pattern: `(?i)(?:(?<!\w)(?:KW)(?!\w).{0,40}CODE|CODE(?=.{0,40}(?<!\w)(?:KW)(?!\w)))(?<!\d)CODE(?!\d)` with keyword list as Python list joined by `\|`.

2. **Keyword set expanded to cover `mecm.yaml` self_tests** — Added `installed|uninstalled` to match existing self_test for 1618 ("Another program is being installed 1618"). Removed `code` (STOPWORD, redundant with `exit code`).

3. **Leak check uses uniform word boundaries per identifier class** — Single boundary regex `(?<![A-Za-z0-9])...(?![A-Za-z0-9])` applied to long identifiers (≥8 chars), IPs, SIDs, and emails. Punctuation (`.`, `-`, `@`, etc.) remains a valid boundary. This preserves correct email/SID behavior while fixing false positives on embedded tokens.

4. **`northwind` added to `COMMON_LABELS` in `engine.py`** — Canonical test domain `laptop-07.northwind.example` splits into labels; `northwind` (9 chars) would otherwise be flagged as leak. This is an implementation detail noted in CHANGELOG.

5. **Test `test_punctuation_boundaries_allowed` rewritten** — Original test used `LS_HOST_1` which no `_spans` regex matches, so `find_leaks` never sees it. New test uses a token that `_spans` matches (e.g., IP `203.0.113.25`) to verify punctuation boundary behavior.

6. **"No behavior change" goal qualified** — Explicitly acknowledged that false-positive edge cases (embedded tokens, hyphen-abutted identifiers) now correctly do not leak. Real leaks (whole tokens) still caught.

### Consciously Rejected Findings

- **test_sid_not_leaked_in_longer_sid "expects no leak" (comp#2, zoom#M2, int_zoom#M2)** — Test correctly asserts leak (`assert "SID..." in leaks`); comment explains hyphen is boundary. Finding misread test.

- **test_punctuation_boundaries_allowed "assertions inverted" (comp#3, zoom#B2, int_zoom#M3)** — Test correctly expects leak for punctuation-abutted tokens. Finding misread `assert "LS_HOST_1" in leaks` as `leaks == []`.

- **Document is "mostly verbatim code" Anti-Weeds violation (zoom#M3, int_zoom#M2)** — Detailed implementation is appropriate for bugfix spec; Detailed Implementation Plan section is the correct place.

- **Cross-line keyword matching not supported (int_zoom#N4)** — 40-char window operates within `search_text()` blob (fields joined with `\n`). Not a defect; `re.DOTALL` would be needed for cross-line, adding complexity.

- **_is_ip() removal "claimed not verified" (zoom#N2)** — Verified: only referenced at `engine.py:418` (branch being removed); safe to delete. Updated design to state this fact.