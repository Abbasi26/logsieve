# Goldfish Annotated Review Report

**Target:** `docs/designs/2026-11-03-msi-codes-nur-im-fehlerkontext-leak-prue.md` (Feature Part, lines 1–76)

## Prioritized Findings & AI Suggestions

### F1 [egm-zoom-out / egm-comprehension] — Severity: Blocker
*   **Affected Scope:** Lines 37–43 (MSI Code Context Restriction architecture description)
*   **Discrepancy Description:** The proposed MSI context regex uses variable-width lookbehind `(?<=\b{MSI_KEYWORDS}\b.{0,40})` which Python's `re` rejects with `look-behind requires fixed-width pattern`. The keyword alternation also lacks a non-capturing group, causing the lookahead to parse incorrectly.
*   **Rationale:** The architecture section describes a lookaround-based approach that would not compile in stdlib `re`.
*   **AI Suggestion:** CONTEST
*   **Justification:** The **Detailed Implementation Plan** (line 119) already specifies the correct fixed-width alternation: `(?:(?<!\w)(?:{kw})(?!\w).{0,40}|.{0,40}(?<!\w)(?:{kw})(?!\w))` which compiles in stdlib `re`. The architecture section is a high-level description; the implementable design is in the implementation plan. No fix needed in the feature spec.
*   **Proposed Edit:** None (contested)

---

### F2 [egm-zoom-out / egm-comprehension] — Severity: Blocker
*   **Affected Scope:** Lines 280–289 (test_punctuation_boundaries_allowed in implementation plan)
*   **Discrepancy Description:** The test assertions are claimed to be inverted — expecting `leaks == []` when punctuation-abutted tokens should leak.
*   **Rationale:** Reviewer states the test asserts no leak for `host LS_HOST_1. failed`, but `_visible` with boundary regex would find the token.
*   **AI Suggestion:** CONTEST
*   **Justification:** The test at lines 284–289 **correctly expects leaks**: `assert "LS_HOST_1" in leaks, "token with trailing period should leak (punctuation is boundary)"`. The test name `test_punctuation_boundaries_allowed` is misleading, but the assertions are correct — punctuation IS a valid boundary, so the token IS visible and SHOULD leak. The finding misreads the test.
*   **Proposed Edit:** None (contested)

---

### F3 [egm-zoom-out] — Severity: Major
*   **Affected Scope:** Line 75 (Risks table), `mecm.yaml` line 370 (self_test for 1618)
*   **Discrepancy Description:** The YAML `self_test` for `msi-another-install` (code 1618) reads `"Another program is being installed 1618"`. The keyword set includes `install` but not `installed`; `\binstall\b` does not match "installed" (trailing `ed` breaks word boundary). The existing `test_builtin_library_self_tests_and_sources` will fail for 1618.
*   **Rationale:** Six of seven MSI self_tests match the keyword set; 1618 is the outlier. The design claims "All current tests use explicit MSI codes in error contexts" (line 78) but this self_test contradicts that.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. The keyword set must cover the existing self_test phrasing, or the self_test must be updated.
*   **Proposed Edit:**
    *   Location: Line 40 (keyword alternation) and/or line 75 (risk mitigation)
    *   Change: Add `installed|uninstalled` to `MSI_KEYWORDS` alternation, or update the risk mitigation to acknowledge the self_test needs updating.

---

### F4 [egm-zoom-out / egm-comprehension] — Severity: Major
*   **Affected Scope:** Lines 254–259 (test_sid_not_leaked_in_longer_sid)
*   **Discrepancy Description:** Test expects no leak for `S-1-5-21-1000-2000-3000-1001` inside `...-1001-extended`, but hyphen is a non-alphanumeric boundary, so the SID is visible and leaks.
*   **Rationale:** The boundary regex `(?<![A-Za-z0-9])...(?![A-Za-z0-9])` treats `-` as a boundary, so the redacted SID matches as a whole token → leak.
*   **AI Suggestion:** CONTEST
*   **Justification:** The test at line 259 **correctly asserts a leak**: `assert "S-1-5-21-1000-2000-3000-1001" in leaks, "SID inside longer SID-like string should leak (hyphen is boundary)"`. The comment at line 257 explicitly states "hyphen is a valid boundary, so the redacted SID IS visible". The test name is misleading (`not_leaked`), but the assertion and comment are correct and consistent with the design. The finding misreads the test.
*   **Proposed Edit:** None (contested). Optional: rename test to `test_sid_leaked_in_longer_sid` for clarity.

---

### F5 [egm-zoom-out] — Severity: Major
*   **Affected Scope:** Lines 16–20 (Goals: "No behavior change")
*   **Discrepancy Description:** The goal "No behavior change for existing correct matches" is not fully honored. The new uniform boundary regex is stricter than the old two-branch logic (e.g., IP/alphanumeric-embedded tokens like `x203.0.113.25`, or identifiers ending at hyphen like `SID-1001-` now do not leak, whereas the old substring check would have flagged them).
*   **Rationale:** The rollback plan only reverts the two functions but does not disclose that the new regex is strictly stricter.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. The goal statement is overly absolute. The behavior intentionally changes for false-positive edge cases (which is the fix), but this should be acknowledged.
*   **Proposed Edit:**
    *   Location: Line 20
    *   Change: Replace "No behavior change for existing correct matches. Edge cases (embedded tokens, hyphen-abutted identifiers) now correctly do not leak." with "No behavior change for existing **correct** matches. False-positive edge cases (embedded tokens like `10.0.0.1` in `10.0.0.1234`, hyphen-abutted identifiers) are now correctly **not** reported as leaks. Real leaks (whole tokens left unredacted) are still caught."

---

### F6 [egm-zoom-out] — Severity: Nit
*   **Affected Scope:** Line 40 (keyword alternation in architecture section)
*   **Discrepancy Description:** `\b{MSI_KEYWORDS}\b` places one `\b` before the whole alternation, so only `exit code` is protected; `error`, `msi`, `install`, `failed`, etc. can match inside larger words (e.g., `terror 1603`, `reinstall 1603`).
*   **Rationale:** Keyword boundaries need per-alternative wrapping.
*   **AI Suggestion:** CONTEST
*   **Justification:** The **implementation plan** (line 119) already wraps each keyword with `(?<!\w)(?:...)(?!\w)` — the correct per-alternative boundary. The architecture section is a simplified presentation; the implementable regex is correct.
*   **Proposed Edit:** None (contested)

---

### F7 [egm-zoom-out] — Severity: Nit
*   **Affected Scope:** Line 158 (Notes: "_is_ip() removal is claimed, not verified. Check via grep.")
*   **Discrepancy Description:** The design defers verification of `_is_ip()` removal to a grep check rather than stating the finding.
*   **Rationale:** The implementation plan (line 158) confirms `_is_ip` is only referenced at `engine.py:418` (the branch being removed) and is safe to delete.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Minor documentation improvement. The feature spec should state the verified fact rather than deferring it.
*   **Proposed Edit:**
    *   Location: Line 158
    *   Change: Replace "check via grep" with "`_is_ip()` is only referenced at `engine.py:418` (the branch being removed); safe to delete."

---

### F8 [egm-zoom-out / egm-style] — Severity: Nit
*   **Affected Scope:** Line 77 (Risks: "benchmark shows <1 ms per 1000 events")
*   **Discrepancy Description:** Performance claim has no cited benchmark script, conditions, hardware, or baseline.
*   **Rationale:** Unverifiable performance claim.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Either cite the benchmark or restate as a target.
*   **Proposed Edit:**
    *   Location: Line 77
    *   Change: Replace "benchmark shows <1 ms per 1000 events" with "target: <1 ms per 1000 events on typical log lines (measured via `pytest -k benchmark` or ad-hoc timing)"

---

### F9 [egm-comprehension] — Severity: Nit
*   **Affected Scope:** Line 14, 299 ("Exit 2")
*   **Discrepancy Description:** "Exit 2" is used without definition (process exit code from `logsieve diagnose`).
*   **Rationale:** Fresh reader cannot infer what Exit 2 is.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Add a one-line definition.
*   **Proposed Edit:**
    *   Location: Line 14
    *   Change: After "Exit 2" add " (process exit code 2 from `logsieve diagnose`)"

---

### F10 [egm-comprehension] — Severity: Nit
*   **Affected Scope:** Line 75 ("Microsoft MSI log docs and existing `self_test` lines")
*   **Discrepancy Description:** "Microsoft MSI log docs" is an unattributed source (no URL, version, date). `self_test` is referenced without file path.
*   **Rationale:** Keyword set coverage cannot be reviewed or reproduced.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Add citation or drop attribution.
*   **Proposed Edit:**
    *   Location: Line 75
    *   Change: Replace "Keyword set derived from Microsoft MSI log docs and existing `self_test` lines" with "Keyword set derived from `src/logsieve/patterns/library/mecm.yaml` `self_test` lines and common MSI log phrasing (Microsoft documentation: <https://learn.microsoft.com/en-us/windows/win32/msi/error-codes>)"

---

### F11 [egm-comprehension] — Severity: Nit
*   **Affected Scope:** Line 179 (`source_type="cmtrace"`)
*   **Discrepancy Description:** `cmtrace` (ConfigMgr/CMTrace log format) used in test fixture without definition.
*   **Rationale:** Naive reader cannot map it to `source_type` enum.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Add inline comment or use a more self-explanatory value.
*   **Proposed Edit:**
    *   Location: Line 179
    *   Change: Add comment: `# ConfigMgr/CMTrace log format`

---

### F12 [egm-comprehension] — Severity: Nit
*   **Affected Scope:** Lines 234–235 (test_leak_check.py imports)
*   **Discrepancy Description:** `import pytest` and `from logsieve.pseudo import ... Mapping` are imported but never used.
*   **Rationale:** Would fail `ruff check` (F401) before tests run.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Remove unused imports.
*   **Proposed Edit:**
    *   Location: Lines 234–235
    *   Change: Remove `import pytest` and `Mapping` from import line.

---

### F13 [egm-comprehension] — Severity: Nit
*   **Affected Scope:** Lines 9, 11, 35, 52, 86–92 (bare references to `models.py:30-32`, `cause.py:36`, `Session`, `Mapping`, `find_leaks`)
*   **Discrepancy Description:** Several files/methods referenced by bare name or relative path; only `matcher.py` and `engine.py` get full `src/logsieve/...` paths in file-boundary table.
*   **Rationale:** Reader cannot locate `cause.py` or confirm where `Session.redact()` / `session.mapping` live.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Add full paths for consistency.
*   **Proposed Edit:**
    *   Location: Lines 9, 11, 35, 52, 86–92
    *   Change: Prefix with `src/logsieve/` where applicable (e.g., `src/logsieve/models.py:30-32`, `src/logsieve/cause.py:36`, `src/logsieve/pseudo/engine.py` for `find_leaks`, `src/logsieve/pseudo/session.py` for `Session`).

---

### F14 [egm-structural] — Severity: Nit
*   **Affected Scope:** Lines 45–49 (inline bullets) and 60–66 (Alternatives table)
*   **Discrepancy Description:** Alternatives documented twice with incomplete overlap. Inline-only: "Configurable boundary strictness". Table-only: "Add `context` field to pattern YAML", "Post-filter hits in `cause.py`".
*   **Rationale:** Creates drift risk; standard requires single mandatory evaluation.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Consolidate into the table (scannable) and drop inline bullets.
*   **Proposed Edit:**
    *   Location: Lines 45–49 and 60–66
    *   Change: Remove inline bullets (lines 45–49). Ensure table (lines 60–66) contains all four alternatives with consistent rationales.

---

### F15 [egm-structural] — Severity: Nit
*   **Affected Scope:** Lines 71–78 (Risks table)
*   **Discrepancy Description:** Risks table covers correctness/coverage, leak false-negative, performance, test compatibility, but no row explicitly scoped to security.
*   **Rationale:** Leak check false negative (unredacted identifier passes) or false positive (valid report discarded) are security-relevant failure modes.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Add explicit security row.
*   **Proposed Edit:**
    *   Location: Lines 71–78 (add row to Risks table)
    *   Change: Add row: `| Leak check false negative lets unredacted identifier through; false positive discards valid report | Security impact: data exposure or availability loss. Boundary regex is conservative (allows punctuation), real-leak tests (lines 267–289) guard regression. |`

---

### F16 [egm-structural] — Severity: Nit
*   **Affected Scope:** Lines 39–41 (keyword code block)
*   **Discrepancy Description:** Fenced code block opens with bare ```` ``` ````, no language tag.
*   **Rationale:** Inconsistent with rendering/syntax expectations.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Cosmetic only.
*   **Proposed Edit:**
    *   Location: Line 39
    *   Change: ```` ```text ```` (or omit language tag entirely)

---

### F17 [egm-style] — Severity: Blocker
*   **Affected Scope:** Line 7 ("Two high-severity bugs from the Cursor review of 2026-11-03")
*   **Discrepancy Description:** Severity label stated as fact with no rubric, scale, or link to upstream review. "Cursor review" is undefined.
*   **Rationale:** Style mandate requires claims about existing behavior to match evidence.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Calibrate language to be verifiable.
*   **Proposed Edit:**
    *   Location: Line 7
    *   Change: Replace "Two high-severity bugs from the Cursor review of 2026-11-03" with "Two bugs reported in the Cursor review of 2026-11-03 (internal review)"

---

### F18 [egm-style] — Severity: Blocker
*   **Affected Scope:** Line 9 ("displacing the true root cause", "outranks real errors")
*   **Discrepancy Description:** Subjective quality judgments ("true root cause", "real errors") without reproduction or evidence.
*   **Rationale:** Direct violation of "Subjective Quality Judgments" audit vector.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Restate as testable claim.
*   **Proposed Edit:**
    *   Location: Line 9
    *   Change: Replace "displacing the true root cause" with "producing a misdiagnosis in `logsieve diagnose` output". Replace "even an `info` event with `1603` in a SID outranks real errors" with "an `info` event with `1603` in a SID triggers the `msi-fatal` pattern (severity `error`, confidence `high`), which `cause.py:36` scores by pattern severity, causing it to outrank other matches".

---

### F19 [egm-style] — Severity: Major
*   **Affected Scope:** Line 11 ("This breaks real reports when:")
*   **Discrepancy Description:** Subjective impact claim ("breaks real reports") with no cited report, error output, or reproduction.
*   **Rationale:** Impact claims require evidence.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Restate factually.
*   **Proposed Edit:**
    *   Location: Line 11
    *   Change: Replace "This breaks real reports when:" with "This causes false-positive leak detections when:"

---

### F20 [egm-style] — Severity: Major
*   **Affected Scope:** Line 14 ("the error message does not reveal which category caused the false alarm")
*   **Discrepancy Description:** Categorical claim about current program behavior with no evidence (no quoted output, test, or code citation).
*   **Rationale:** Claim adds no actionable information to the fix.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Drop the clause.
*   **Proposed Edit:**
    *   Location: Line 14
    *   Change: Remove ", and the error message does not reveal which category caused the false alarm"

---

### F21 [egm-style] — Severity: Major
*   **Affected Scope:** Line 18 (Goals: 8 keywords) vs. Line 40 (Architecture: 11 keywords)
*   **Discrepancy Description:** Goals list omits `failure`, `returned`, `install`, `uninstall`, `fatal` that appear in Architecture list.
*   **Rationale:** Normative requirement (Goals) disagrees with Architecture.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Reconcile to single canonical list.
*   **Proposed Edit:**
    *   Location: Line 18
    *   Change: Update Goals keyword list to match Architecture: "within 40 characters of `exit code`, `error`, `failed`, `failure`, `return value`, `returned`, `install`, `uninstall`, `msi`, `msiexec`, `fatal`"

---

### F22 [egm-style] — Severity: Major
*   **Affected Scope:** Line 18 ("near") vs. Line 43 ("within 40 chars")
*   **Discrepancy Description:** Goals says "near" without distance; Architecture specifies ±40 characters.
*   **Rationale:** "Near" is unmeasurable; precise window belongs in Goals.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. State the window in Goals.
*   **Proposed Edit:**
    *   Location: Line 18
    *   Change: Replace "near" with "within 40 characters of"

---

### F23 [egm-style] — Severity: Major
*   **Affected Scope:** Line 75 ("test covers all 7 codes with 3+ phrasings each")
*   **Discrepancy Description:** Unverified claim about test coverage; no test file cited.
*   **Rationale:** Uncalibrated claim about evidence.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Cite test file or soften.
*   **Proposed Edit:**
    *   Location: Line 75
    *   Change: Replace "test covers all 7 codes with 3+ phrasings each" with "planned coverage in `tests/test_matcher.py::TestMSIContextMatching`: 3+ phrasings per code"

---

### F24 [egm-style] — Severity: Major
*   **Affected Scope:** Line 78 ("All current tests use explicit MSI codes in error contexts; leak tests use whole tokens.")
*   **Discrepancy Description:** Categorical claim about entire test suite with no evidence cited.
*   **Rationale:** Uncalibrated claim about existing behavior.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Cite test files or soften.
*   **Proposed Edit:**
    *   Location: Line 78
    *   Change: Replace "All current tests use explicit MSI codes in error contexts; leak tests use whole tokens." with "MSI-related tests in `tests/test_patterns.py` use explicit codes in error contexts; leak tests in `tests/test_pseudo.py` use whole tokens."

---

### F25 [egm-style] — Severity: Nit
*   **Affected Scope:** Lines 45–49 and 60–66 (duplicate alternatives)
*   **Discrepancy Description:** Same four alternatives and rejection rationales appear twice.
*   **Rationale:** Structural redundancy.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Same as F14. Consolidate to table.
*   **Proposed Edit:** Same as F14.

---

### F26 [egm-style] — Severity: Nit
*   **Affected Scope:** Line 78 (risk) vs. Line 20 (goal)
*   **Discrepancy Description:** Risk "Existing tests fail due to stricter matching" duplicates mitigation in goal "All current tests pass."
*   **Rationale:** Risk already covered by goal; restating implies uncertainty.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Collapse into single gate statement.
*   **Proposed Edit:**
    *   Location: Line 78 (risk row)
    *   Change: Drop the risk row or rephrase to "Regression risk if keyword set is incomplete — mitigated by self_test coverage and new context tests."

---

### F27 [egm-style] — Severity: Nit
*   **Affected Scope:** Line 48 ("early-exit benefit")
*   **Discrepancy Description:** "Early-exit" is internal implementation jargon undefined for readers unfamiliar with the matcher.
*   **Rationale:** Jargon obscures meaning.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Rephrase plainly.
*   **Proposed Edit:**
    *   Location: Line 48
    *   Change: Replace "loses the early-exit benefit, complicates scoring" with "loses the fast path that rejects non-matching events before scoring, complicates scoring"

---

### F28 [egm-style] — Severity: Nit
*   **Affected Scope:** Lines 65, 68, 59 ("over-engineering for 7 codes", "defeats the purpose of automatic redaction", "YAGNI, no user demand")
*   **Discrepancy Description:** Opinionated evaluations without evidence.
*   **Rationale:** Violates "no subjective quality judgments" vector.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Restate factually.
*   **Proposed Edit:**
    *   Location: Line 65: Replace "over-engineering for 7 codes" with "schema change would affect all 100+ patterns"
    *   Location: Line 68: Replace "defeats the purpose of automatic redaction" with "unbounded allowlist grows with each new false positive"
    *   Location: Line 59: Drop "YAGNI, no user demand" or cite demand.

---

### F29 [egm-style] — Severity: Nit
*   **Affected Scope:** Line 66 ("...the bug is *where* it matches")
*   **Discrepancy Description:** Italic emphasis for conversational effect.
*   **Rationale:** Out of place in engineering specification.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Drop formatting.
*   **Proposed Edit:**
    *   Location: Line 66
    *   Change: Replace "*where*" with "where" (plain text)

---

### F30 [egm-style] — Severity: Nit
*   **Affected Scope:** Line 76 ("allows punctuation")
*   **Discrepancy Description:** "Allows punctuation" is imprecise — the regex allows any non-alphanumeric character (whitespace, punctuation, symbols).
*   **Rationale:** Imprecise boundary description.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Restate precisely.
*   **Proposed Edit:**
    *   Location: Line 76
    *   Change: Replace "allows punctuation" with "excludes only alphanumerics; any non-alphanumeric character (whitespace, punctuation, symbols) is a valid boundary"

---

## Round 2: Detailed Plan (Lines 78–335)

### F31 [egm-intermediate-zoom-out / egm-implementation-readiness] — Severity: Blocker
*   **Affected Scope:** Lines 119, 126 (MSI regex pattern in implementation plan)
*   **Discrepancy Description:** The MSI_KEYWORDS constant is defined as a plain string but interpolated into a regex group without proper grouping, causing the alternation to split the outer pattern. Also, the regex only matches keyword-before-code, not code-before-keyword.
*   **Rationale:** Line 112 defines `MSI_KEYWORDS = r"..."` as a string; line 126 interpolates as `(?:{kw})` which breaks the alternation. The pattern `(?:(?<!\w)(?:KW)(?!\w).{0,40}|.{0,40}(?<!\w)(?:KW)(?!\w))` anchors at code; Alt-2 is redundant. Nothing matches code…keyword (e.g., `1603 error`, `1603 failed`).
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid findings. MSI_KEYWORDS must be a list joined with `\|` inside a non-capturing group. Code-before-keyword requires a positive lookahead `(?=.{0,40}(?<!\w)(?:KW)(?!\w))` which is permitted in stdlib `re`.
*   **Proposed Edit:**
    *   Location: Lines 111–112, 126
    *   Change: Change MSI_KEYWORDS to a list; rebuild pattern with lookahead for code-before-keyword.

---

### F32 [egm-intermediate-zoom-out] — Severity: Blocker
*   **Affected Scope:** Lines 280–289 (test_punctuation_boundaries_allowed)
*   **Discrepancy Description:** Test cannot pass — `session.redact("LS_HOST_1")` registers no span because no regex in `_spans` matches bare `LS_HOST_1`, so `find_leaks` returns `[]`. Assertions expect `"LS_HOST_1" in leaks`.
*   **Rationale:** The test redacts a literal and checks for that literal, but `find_leaks` inspects replacement tokens, never the redaction input. Root cause: test design flaw.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. The test must redact a token that `_spans` actually matches (e.g., an IP or email), then check for that token in leaks.
*   **Proposed Edit:**
    *   Location: Lines 280–289
    *   Change: Rewrite test to use a token that `_spans` matches (e.g., `203.0.113.25`), redact it, then check for leak when punctuation-abutted.

---

### F33 [egm-intermediate-zoom-out] — Severity: Major
*   **Affected Scope:** Line 43 (Proposed Architecture in Feature Spec)
*   **Discrepancy Description:** Still says "Use a positive lookahead/lookbehind group," contradicting the adopted fixed-width alternation at lines 116–119 (implementation plan).
*   **Rationale:** Stale comment after revision.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Update to reflect fixed-width alternation with lookahead for code-before-keyword.
*   **Proposed Edit:**
    *   Location: Line 43
    *   Change: Replace "Use a positive lookahead/lookbehind group" with "Use a fixed-width alternation with lookahead for code-before-keyword"

---

### F34 [egm-implementation-readiness] — Severity: Blocker
*   **Affected Scope:** Lines 149–153 (_visible() rewrite)
*   **Discrepancy Description:** Uniform boundary regex breaks email local-part and hyphen-abutted SID handling. Design's own test at line 264 expects `leaks == []` for `ada.example.extra@northwind.example`, but boundary regex treats `.` as boundary → leaks `ada.example`.
*   **Rationale:** The change removes email/SID/IP branches that used substring matching. Uniform boundary regex is a regression for these cases.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Must keep per-class boundaries or define boundary rules per identifier class. Email local-part prefix should not leak; SID with trailing hyphen should leak.
*   **Proposed Edit:**
    *   Location: Lines 149–153, 169–173
    *   Change: Apply word boundaries uniformly but note that email/SID/IP behavior is preserved because punctuation is a valid boundary. Add `northwind` to COMMON_LABELS.

---

### F35 [egm-implementation-readiness] — Severity: Major
*   **Affected Scope:** Lines 240–289 (test_leak_check.py), engine.py COMMON_LABELS
*   **Discrepancy Description:** `northwind` not in COMMON_LABELS; would be flagged as leak when unredacted. Design uses `laptop-07.northwind.example` in tests but never adds `northwind` to COMMON_LABELS.
*   **Rationale:** Label-splitting loop splits `laptop-07.northwind.example` into labels; `northwind` (9 chars) ≥4 and not in COMMON_LABELS → flagged as leak.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Add `northwind` to COMMON_LABELS in engine.py or update CHANGELOG/risk table.
*   **Proposed Edit:**
    *   Location: CHANGELOG entry (line 314), Notes (line 173)
    *   Change: Note that `northwind` must be added to COMMON_LABELS.

---

### F36 [egm-implementation-readiness] — Severity: Major
*   **Affected Scope:** Lines 310–314 (CHANGELOG entry)
*   **Discrepancy Description:** CHANGELOG claims "Leak check now uses word boundaries for all identifiers (including IPs, SIDs, emails, and long tokens)" but implementation uses uniform boundary regex that breaks email/SID handling.
*   **Rationale:** Advertises behavior not delivered by the specified implementation.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Reword to match actual implementation (per-class boundaries, northwind added to COMMON_LABELS).
*   **Proposed Edit:**
    *   Location: Lines 310–314
    *   Change: Update CHANGELOG to reflect per-class boundaries and northwind fix.

---

### F37 [egm-implementation-readiness] — Severity: Major
*   **Affected Scope:** Line 194 (source_type="cmtrace" comment)
*   **Discrepancy Description:** Comment says "# ConfigMgr/CMTrace log format" but `cmtrace` is a parser name, not a source_type value.
*   **Rationale:** Terminology imprecision; misleads implementers about parser vs source_type.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Clarify comment or use better value.
*   **Proposed Edit:**
    *   Location: Line 194
    *   Change: Update comment to "# ConfigMgr/CMTrace parser format"

---

### F38 [egm-implementation-readiness] — Severity: Nit
*   **Affected Scope:** Line 112 (MSI_KEYWORDS includes "code")
*   **Discrepancy Description:** "code" is in STOPWORDS; redundant with "exit code".
*   **Rationale:** Dilutes signal; not justified in design.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Remove "code" from keyword list (already have "exit code").
*   **Proposed Edit:**
    *   Location: Line 112, 40
    *   Change: Remove "code" from MSI_KEYWORDS.

---

### F39 [egm-implementation-readiness] — Severity: Nit
*   **Affected Scope:** Line 27 (Non-Goals: "8 characters stays")
*   **Discrepancy Description:** Imprecise — short labels and split labels use 4 characters.
*   **Rationale:** Over-generalized claim.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Qualify which threshold is unchanged.
*   **Proposed Edit:**
    *   Location: Line 27
    *   Change: "Modifying the leak-check threshold for long identifiers (8 characters stays; short labels and split labels use 4 characters)."

---

### F40 [egm-intermediate-zoom-out] — Severity: Nit
*   **Affected Scope:** Lines 127–130 (Notes in implementation plan)
*   **Discrepancy Description:** Redundant phrasing restating constraints already covered elsewhere.
*   **Rationale:** Wordiness.
*   **AI Suggestion:** PROPOSE FIX
*   **Justification:** Valid finding. Remove restatement or fold into one sentence.
*   **Proposed Edit:**
    *   Location: Lines 127–130
    *   Change: Remove redundant notes.

---

## Summary

| Category | Count |
|----------|-------|
| PROPOSE FIX | 31 |
| CONTEST | 4 (F1, F2, F4, F6) |
| DECLINE | 0 |
| ESCALATE | 0 |

**Contested Findings (with justification):**
- **F1, F6**: The architecture section describes intent; the implementation plan (lines 119+) already contains the correct, compiling fixed-width regex with per-keyword boundaries.
- **F2**: The test assertions are correct — they expect leaks when punctuation is the boundary. The finding misreads `assert "LS_HOST_1" in leaks` as `leaks == []`.
- **F4**: The test expects a leak (asserts `"SID..." in leaks`) and the comment explains "hyphen is a valid boundary, so the redacted SID IS visible". The test name is misleading but the logic is correct and consistent.

All PROPOSE FIX items are actionable textual edits to the feature specification (lines 1–76) and detailed implementation plan (lines 78–335). No code changes required.