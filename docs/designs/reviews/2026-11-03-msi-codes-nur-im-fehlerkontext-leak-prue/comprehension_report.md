# Stage 6: Comprehension Test
### Reviewer: egm-comprehension (Modell: `kilo/kilo-auto/free`, frischer Prozess)



## What this proposes

The document proposes two internal bugfixes for `logsieve diagnose`. First, the seven short decimal MSI codes (`1602`, `1603`, `1605`, `1618`, `1633`, `1638`, `1642`) will only match when an error/install keyword (`exit code`, `error`, `failed`, `return value`, `msi`, `msiexec`, `fatal`, …) appears within 40 characters, implemented as a lookahead/lookbehind regex inside `matcher.py:_code_regexes()`. Second, the leak check in `engine.py:_visible()` switches from substring matching to word-boundary matching for all identifiers, so IPs/hostnames/SIDs/emails that appear only as substrings inside version strings or compound tokens (e.g. `10.0.0.1` inside `10.0.0.1234`) no longer trigger a false Exit 2. The changes are internal — no schema, CLI, or threshold changes — backed by two new test files, and they must keep all existing tests passing.

## How the existing system works, per this document

Currently `_code_regexes()` wraps every decimal code in a digit-boundary regex `(?<!\d)CODE(?!\d)`, so an MSI code matches anywhere it appears as a standalone number — including inside SIDs, thread IDs, and build numbers — and because `models.py:30-32` concatenates `user` into the searched blob, a SID ending in `1603` fires the `msi-fatal` pattern. The leak check in `_visible()` uses a plain substring test (`original.casefold() in text.casefold()`) for any identifier ≥8 chars or any IP/SID/email, so a redacted value that survives as a substring of a longer token is reported as a leak, the report is discarded with Exit 2, and the error does not say which category caused it. Short identifiers (<8 chars) already use a word-boundary regex, and `cause.py:36` scores hits by pattern severity rather than event severity, so a spurious MSI match can outrank real errors.

## Findings

### 1. 🔴 Blocker — The proposed MSI context regex cannot compile in Python `re`
- **Affected scope:** `src/logsieve/patterns/matcher.py` change, lines 107–122 (pattern at line 119, notes at 125–129)
- **Discrepancy & rationale:** The lookbehind `(?<=\b{MSI_KEYWORDS}\b.{0,40})` is variable width — both because of `.{0,40}` and because the keyword alternation spans different lengths (`exit code` vs `error`). Python's stdlib `re` rejects variable-width lookbehind with `re.error: look-behind requires fixed-width pattern`, so `re.compile(pattern)` raises and `_code_regexes()` crashes for all seven MSI codes. That means `load_builtin()` fails and every test in `test_matcher.py` errors at the fixture (all seven codes × three positive contexts). Compounding this, the keyword alternation is not wrapped in a non-capturing group: `(?=.{0,40}\bexit code|error|failed|…)` parses as `(?=.{0,40}\bexit code)|(error)|(failed)|…`, so every alternative after the first must appear *immediately* after the code rather than within 40 chars — the lookahead/lookbehind would not implement the stated ±40-char rule even if it compiled. The pattern needs a fixed-width-safe structure (or the `regex` third-party module) and the keywords wrapped in `(?:…)`.

### 2. 🔴 Major — `test_sid_not_leaked_in_longer_sid` contradicts the boundary algorithm
- **Affected scope:** `tests/test_leak_check.py`, lines 254–259
- **Discrepancy & rationale:** The test redacts `S-1-5-21-1000-2000-3000-1001` and asserts no leak against text `…-1001-extended`. Under the proposed `_visible`, the boundary regex `(?<![A-Za-z0-9])…(?![A-Za-z0-9])` treats the trailing `-` as a valid boundary (hyphen is not alphanumeric), so the redacted SID matches as a whole token and `find_leaks` returns it — the assertion `leaks == []` fails. The design's own boundary definition (line 54) explicitly allows punctuation as a boundary, so an extended SID is *not* the "substring inside a compound token" case the fix targets; the test expectation is incompatible with the chosen algorithm.

### 3. 🔴 Major — `test_punctuation_boundaries_allowed` assertions are inverted
- **Affected scope:** `tests/test_leak_check.py`, lines 280–289
- **Discrepancation & rationale:** The test redacts `LS_HOST_1`, then passes text that still contains `LS_HOST_1` literally (`host LS_HOST_1. failed`, `(LS_HOST_1)`, `[LS_HOST_1]`) and asserts `leaks == []` ("should not leak"). Per the documented semantics (and the sibling test at lines 267–272), a token that is still present in the output *is* the leak. The risk table at line 76 states the opposite intent: this exact scenario (token abutting punctuation) must *still be caught* so the boundary regex is not over-strict. The assertions need `assert "LS_HOST_1" in leaks`.

### 4. 🟡 Nit — `Exit 2` is used without definition
- **Affected scope:** lines 14, 299
- **Discrepancy & rationale:** "Both trigger Exit 2, the report is discarded" and the changelog reference assume the reader knows what Exit 2 is (the process exit code, presumably, and which command emits it). A fresh reader has to infer it; a one-line definition or a link to the CLI exit-code table would close the gap.

### 5. 🟡 Nit — Undefined `self_test` and unlinked "Microsoft MSI log docs"
- **Affected scope:** line 75
- **Discrepancy & rationale:** The mitigation claims the keyword set is "derived from Microsoft MSI log docs and existing `self_test` lines". Neither is defined or linked: `self_test` is referenced as if its location and contents are known, and "Microsoft MSI log docs" is a vague external source with no URL, so the keyword set's coverage cannot be reviewed or reproduced from the document.

### 6. 🟡 Nit — `cmtrace` is undefined in the test fixture
- **Affected scope:** line 178 (`source_type="cmtrace"`)
- **Discrepancy & rationale:** `cmtrace` (and the `AppEnforce.log` source) are ConfigMgr/CMTrace-specific terms used in the illustrative test code with no definition or link. It is not central to the design, but a naive reader cannot map it to the `source_type` enum.

### 7. 🟡 Nit — Unused imports would fail the `ruff check` gate
- **Affected scope:** `tests/test_leak_check.py`, lines 234–235
- **Discrepancy & rationale:** `import pytest` and `from logsieve.pseudo import … Mapping` are imported but never used in the shown tests (no decorators, no `Mapping` reference). The verification checklist at line 325 requires `ruff check .` to pass, so these would be flagged F401 before the suite even runs.

### 8. 🟡 Nit — Several referenced files/methods have no path or definition
- **Affected scope:** lines 9, 11, 35, 52, 86–92
- **Discrepancy & rationale:** `models.py:30-32`, `cause.py:36`, `Session`, `Mapping`, and `find_leaks` are referenced by bare name or relative path; only `matcher.py` and `engine.py` get full `src/logsieve/…` paths in the file-boundary table. A reader cannot locate `cause.py` or confirm where `Session.redact()` / `session.mapping` live (the test imports them from `logsieve.pseudo`, which the design narrative never explains).

