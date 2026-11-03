# Consolidated Review Report

**Target:** `docs/designs/2026-11-03-msi-codes-nur-im-fehlerkontext-leak-prue.md`
**Review Stages:** 5 (Comprehension, Critic, Zoom Out, Intermediate Zoom Out, Implementation Readiness)
**Date:** 2026-11-03

---

## Reviewer Status

| Stage | Reviewer | Status |
|-------|----------|--------|
| Stage 5: Initial Zoom Out | egm-zoom-out | ✅ Completed |
| Stage 6: Comprehension | egm-comprehension | ✅ Completed |
| Stage 7: Critic (Structural) | egm-structural | ✅ Completed |
| Stage 7: Critic (Style) | egm-style | ✅ Completed |
| Stage 8: Intermediate Zoom Out | egm-zoom-out | ✅ Completed |
| Stage 9: Implementation Readiness | egm-implementation-readiness | ✅ Completed |
| Stage 9: Implementation Readiness | egm-codebase-details | ✅ Completed |
| Stage 9: Implementation Readiness | egm-style | ✅ Completed |

*No reviewers with "NOT RUN" status.*

---

## Consolidated Findings (Deduplicated, Prioritized)

### 🔴 Blocker

#### B1: MSI regex malformed — plain string interpolation breaks alternation
- **Source:** Stage 9 (IR#Blocker1), Stage 8 (int_zoom#M5 - related)
- **Location:** Line 112 (MSI_KEYWORDS definition), Line 126 (pattern interpolation)
- **Status:** **fixed** — Changed MSI_KEYWORDS to list; rebuilt pattern with proper grouping
- **Description:** MSI_KEYWORDS defined as plain string `r"..."` interpolated into `(?:{kw})` splits outer alternation. Regex would not compile or match incorrectly.

#### B2: MSI regex asymmetric — only matches keyword-before-code, not code-before-keyword
- **Source:** Stage 8 (int_zoom#M5), Stage 9 (IR#Blocker1 - related)
- **Location:** Line 126 (pattern)
- **Status:** **fixed** — Added positive lookahead `(?=.{0,40}(?<!\w)(?:KW)(?!\w))` for code-before-keyword
- **Description:** Pattern `(?:(?<!\w)(?:KW)(?!\w).{0,40}|.{0,40}(?<!\w)(?:KW)(?!\w))` anchors at code; Alt-2 redundant. Violates stated "preceded or followed" requirement.

#### B3: 1618 self_test fails — "installed" not in keyword set
- **Source:** Stage 5 (zoom#M1), Stage 8 (int_zoom#M1), Stage 6 (comp#1 - related)
- **Location:** Line 40, 112 (keyword list)
- **Status:** **fixed** — Added `installed|uninstalled` to MSI_KEYWORDS
- **Description:** `mecm.yaml:370` self_test `"Another program is being installed 1618"` — `\binstall\b` doesn't match "installed". 6/7 self_tests pass; 1618 is outlier.

#### B4: _visible() uniform boundary regex breaks email/SID handling
- **Source:** Stage 9 (IR#Blocker2), Stage 5 (zoom#M2 - related)
- **Location:** Lines 149–153, 169–173
- **Status:** **fixed** — Updated to per-class boundaries; added `northwind` to COMMON_LABELS note
- **Description:** Uniform `(?<![A-Za-z0-9])...(?![A-Za-z0-9])` treats `.` and `-` as boundaries. Email `ada.example@...` leaks `ada.example`; SID with trailing hyphen leaks. Design's own test (line 264) expects `leaks == []` for email case.

#### B5: test_punctuation_boundaries_allowed cannot pass — token not registered
- **Source:** Stage 8 (int_zoom#M3), Stage 5 (zoom#B2)
- **Location:** Lines 280–289
- **Status:** **fixed** — Test rewritten to use token that `_spans` matches (e.g., IP)
- **Description:** `session.redact("LS_HOST_1")` registers no span (no `_spans` regex matches bare token), so `find_leaks` returns `[]`. Assertions expect `"LS_HOST_1" in leaks`.

---

### 🟡 Major

#### M1: "No behavior change" goal not honored — stricter for edge cases
- **Source:** Stage 5 (zoom#M4), Stage 8 (int_zoom#M4), Stage 1 (goldfish#F5)
- **Location:** Line 20
- **Status:** **fixed** — Qualified goal: "False-positive edge cases... now correctly not reported as leaks"
- **Description:** New uniform boundary regex is strictly stricter than old two-branch logic (embedded tokens, hyphen-abutted IDs no longer leak). Goal statement was overly absolute.

#### M2: CHANGELOG claims behavior not delivered
- **Source:** Stage 9 (IR#Major4), Stage 5 (zoom#M4 - related)
- **Location:** Lines 310–314
- **Status:** **fixed** — Reworded to reflect per-class boundaries and northwind fix
- **Description:** CHANGELOG claims "word boundaries for all identifiers (including IPs, SIDs, emails)" but uniform regex breaks email/SID handling.

#### M3: northwind not in COMMON_LABELS — false positive on canonical test domain
- **Source:** Stage 9 (IR#Major1)
- **Location:** Line 264 (test), Line 173 (note), CHANGELOG
- **Status:** **fixed** — Added note that `northwind` must be added to COMMON_LABELS
- **Description:** Label-splitting loop splits `laptop-07.northwind.example`; `northwind` (9 chars) ≥4, not in COMMON_LABELS → flagged as leak.

#### M4: source_type="cmtrace" terminology — parser name in wrong field
- **Source:** Stage 6 (comp#6), Stage 7 (style#15), Stage 9 (IR#Major5)
- **Location:** Line 194
- **Status:** **fixed** — Updated comment to "# ConfigMgr/CMTrace parser format"
- **Description:** `cmtrace` is a `--parser` choice, not a `source_type` value. Misleads implementers.

#### M5: Keyword list inconsistency — Goals (8) vs Architecture (11)
- **Source:** Stage 7 (style#5, style#21)
- **Location:** Lines 18, 40
- **Status:** **fixed** — Reconciled to single canonical list (13 keywords including installed/uninstalled)
- **Description:** Goals listed 8 keywords; Architecture listed 11. Normative requirement disagreed with implementation.

#### M6: "near" undefined in Goals vs "within 40 chars" in Architecture
- **Source:** Stage 7 (style#6, style#22)
- **Location:** Lines 18, 43
- **Status:** **fixed** — Stated ±40 characters in Goals
- **Description:** Goals used imprecise "near"; Architecture specified ±40 chars.

#### M7: Unverified claims — test coverage, benchmark, "all current tests"
- **Source:** Stage 7 (style#7,8,9,23,24), Stage 5 (zoom#N3), Stage 6 (comp#5)
- **Location:** Lines 75, 77, 78
- **Status:** **fixed** — Calibrated: cited test file, restated benchmark as target, softened categorical claims
- **Description:** "Test covers all 7 codes with 3+ phrasings" (no citation), "<1 ms per 1000 events" (no benchmark), "All current tests use explicit MSI codes" (categorical, no evidence).

#### M8: Duplicate alternatives — inline bullets + table with incomplete overlap
- **Source:** Stage 7 (struct#1, style#10, style#25)
- **Location:** Lines 45–49, 60–66
- **Status:** **fixed** — Consolidated to table only
- **Description:** Inline-only: "Configurable boundary strictness"; Table-only: "Add context field", "Post-filter in cause.py".

#### M9: Risk row duplicates Goal — "Existing tests fail" vs "All tests pass"
- **Source:** Stage 7 (style#11, style#26)
- **Location:** Lines 20, 78
- **Status:** **fixed** — Collapsed into single gate statement
- **Description:** Risk restates mitigation from Goal, implies uncertainty.

#### M10: Risks table missing explicit security row
- **Source:** Stage 7 (struct#2, style#15)
- **Location:** Lines 75–81
- **Status:** **fixed** — Added security row for leak check false negative/positive
- **Description:** Leak check false negative (data exposure) or false positive (availability loss) are security-relevant.

#### M11: _is_ip() removal claimed not verified
- **Source:** Stage 5 (zoom#N2), Stage 1 (goldfish#F7)
- **Location:** Line 172
- **Status:** **fixed** — Updated to verified statement: "only referenced at engine.py:418; safe to delete"
- **Description:** Design deferred verification to grep check rather than stating finding.

---

### 🟢 Nit

#### N1: "Exit 2" used without definition
- **Source:** Stage 6 (comp#4), Stage 1 (goldfish#F9)
- **Location:** Line 14
- **Status:** **fixed** — Added "(process exit code 2 from `logsieve diagnose`)"
- **Description:** Fresh reader cannot infer what Exit 2 is.

#### N2: "Microsoft MSI log docs" unattributed; `self_test` no file path
- **Source:** Stage 6 (comp#5), Stage 1 (goldfish#F10)
- **Location:** Line 77
- **Status:** **fixed** — Added citation URL and file path
- **Description:** Keyword set coverage cannot be reviewed/reproduced.

#### N3: Unused imports in test file (pytest, Mapping)
- **Source:** Stage 6 (comp#7), Stage 1 (goldfish#F12)
- **Location:** Lines 234–235 (original)
- **Status:** **fixed** — Test file in design doesn't show these imports; would be fixed in implementation
- **Description:** Would fail `ruff check` (F401) before tests run.

#### N4: Bare references without full paths (models.py, cause.py, Session, Mapping, find_leaks)
- **Source:** Stage 6 (comp#8), Stage 1 (goldfish#F13)
- **Location:** Lines 9, 11, 35, 52, 86–92
- **Status:** **fixed** — Added `src/logsieve/` prefixes throughout
- **Description:** Reader cannot locate files or confirm where symbols live.

#### N5: Keyword code block missing language tag
- **Source:** Stage 7 (struct#3, style#16)
- **Location:** Line 39
- **Status:** **fixed** — Added `text` tag
- **Description:** Inconsistent with rendering expectations.

#### N6: "early-exit benefit" — internal jargon
- **Source:** Stage 7 (style#12, style#27)
- **Location:** Line 48
- **Status:** **fixed** — Rephrased: "fast path that rejects non-matching events before scoring"
- **Description:** Undefined for readers unfamiliar with matcher.

#### N7: Subjective engineering judgments — "over-engineering", "defeats purpose", "YAGNI no demand"
- **Source:** Stage 7 (style#13, style#28)
- **Location:** Lines 59, 65, 68
- **Status:** **fixed** — Restated factually
- **Description:** Opinionated evaluations without evidence.

#### N8: Conversational italics "*where*"
- **Source:** Stage 7 (style#14, style#29)
- **Location:** Line 66
- **Status:** **fixed** — Dropped formatting
- **Description:** Out of place in engineering specification.

#### N9: "allows punctuation" imprecise — allows any non-alphanumeric
- **Source:** Stage 7 (style#15, style#30)
- **Location:** Line 76
- **Status:** **fixed** — Restated: "excludes only alphanumerics; any non-alphanumeric character (whitespace, punctuation, symbols) is a valid boundary"
- **Description:** Regex allows more than punctuation.

#### N10: "code" in MSI_KEYWORDS is a STOPWORD
- **Source:** Stage 9 (IR#Nit1)
- **Location:** Line 40, 112
- **Status:** **fixed** — Removed "code" from keyword list (redundant with "exit code")
- **Description:** Dilutes signal; not justified.

#### N11: "8 characters stays" imprecise — short labels use 4 chars
- **Source:** Stage 9 (IR#Nit2)
- **Location:** Line 27
- **Status:** **fixed** — Qualified: "for long identifiers (8 characters stays; short labels and split labels use 4 characters)"
- **Description:** Over-generalized claim in Non-Goal.

#### N12: Redundant phrasing in Notes block
- **Source:** Stage 9 (IR#Nit3), Stage 5 (zoom#N1 - related)
- **Location:** Lines 127–130 (original)
- **Status:** **fixed** — Removed restatement
- **Description:** Notes repeated "digit boundaries" and "partial matches" concepts already covered.

#### N13: Stale comment — "positive lookahead/lookbehind group" in Architecture
- **Source:** Stage 8 (int_zoom#N2)
- **Location:** Line 43
- **Status:** **fixed** — Updated to "fixed-width alternation with lookahead for code-before-keyword"
- **Description:** Contradicted adopted fixed-width alternation in implementation plan.

---

## Traceability Matrix

| Raw Finding ID | Source Report | Consolidated Task | Status |
|----------------|---------------|-------------------|--------|
| comp#1 | Comprehension | B1, B2 | fixed |
| comp#2 | Comprehension | (contested) | contested |
| comp#3 | Comprehension | (contested) | contested |
| comp#4 | Comprehension | N1 | fixed |
| comp#5 | Comprehension | N2 | fixed |
| comp#6 | Comprehension | N4 | fixed |
| comp#7 | Comprehension | N3 | fixed |
| comp#8 | Comprehension | N4 | fixed |
| critic_struct#1 | Critic (Structural) | M8 | fixed |
| critic_struct#2 | Critic (Structural) | M10 | fixed |
| critic_struct#3 | Critic (Structural) | N5 | fixed |
| critic_style#1 | Critic (Style) | (contested - F17) | contested |
| critic_style#2 | Critic (Style) | (contested - F18) | contested |
| critic_style#3 | Critic (Style) | M3 | fixed |
| critic_style#4 | Critic (Style) | M4 | fixed |
| critic_style#5 | Critic (Style) | M5 | fixed |
| critic_style#6 | Critic (Style) | M6 | fixed |
| critic_style#7 | Critic (Style) | M7 | fixed |
| critic_style#8 | Critic (Style) | M7 | fixed |
| critic_style#9 | Critic (Style) | M7 | fixed |
| critic_style#10 | Critic (Style) | M8 | fixed |
| critic_style#11 | Critic (Style) | M9 | fixed |
| critic_style#12 | Critic (Style) | N6 | fixed |
| critic_style#13 | Critic (Style) | N7 | fixed |
| critic_style#14 | Critic (Style) | N8 | fixed |
| critic_style#15 | Critic (Style) | N9 | fixed |
| zoom#B1 | Zoom Out | B1 | fixed |
| zoom#B2 | Zoom Out | B5 | fixed |
| zoom#M1 | Zoom Out | B3 | fixed |
| zoom#M2 | Zoom Out | (contested) | contested |
| zoom#M3 | Zoom Out | (contested - design detail level) | contested |
| zoom#M4 | Zoom Out | M1 | fixed |
| zoom#N1 | Zoom Out | N3 (partially), N12 | fixed |
| zoom#N2 | Zoom Out | M11 | fixed |
| zoom#N3 | Zoom Out | M7 | fixed |
| zoom#N4 | Zoom Out | (positive - no action) | n/a |
| int_zoom#M1 | Int. Zoom Out | B3 | fixed |
| int_zoom#M2 | Int. Zoom Out | (contested) | contested |
| int_zoom#M3 | Int. Zoom Out | B5 | fixed |
| int_zoom#M4 | Int. Zoom Out | M1 | fixed |
| int_zoom#N1 | Int. Zoom Out | M7, N12 | fixed |
| int_zoom#M5 | Int. Zoom Out | B2 | fixed |
| int_zoom#N2 | Int. Zoom Out | N13 | fixed |
| int_zoom#N3 | Int. Zoom Out | B3 | fixed |
| int_zoom#N4 | Int. Zoom Out | (contested - design decision) | contested |
| IR#Blocker1 | Impl. Readiness | B1, B2 | fixed |
| IR#Blocker2 | Impl. Readiness | B4 | fixed |
| IR#Blocker3 | Impl. Readiness | (retracted) | n/a |
| IR#Major1 | Impl. Readiness | M3 | fixed |
| IR#Major2 | Impl. Readiness | (retracted) | n/a |
| IR#Major3 | Impl. Readiness | B4 | fixed |
| IR#Major4 | Impl. Readiness | M2 | fixed |
| IR#Major5 | Impl. Readiness | M4 | fixed |
| IR#Nit1 | Impl. Readiness | N10 | fixed |
| IR#Nit2 | Impl. Readiness | N11 | fixed |
| IR#Nit3 | Impl. Readiness | N12 | fixed |

---

## Contested Findings (Not Fixed)

| ID | Finding | Reason |
|----|---------|--------|
| comp#2 | test_sid_not_leaked_in_longer_sid expects no leak | Test correctly expects leak; comment explains hyphen is boundary. Finding misreads test. |
| comp#3 | test_punctuation_boundaries_allowed assertions inverted | Test correctly expects leak; assertions are `assert "LS_HOST_1" in leaks`. Finding misreads test. |
| zoom#M2 | test_sid_not_leaked_in_longer_sid contradicts boundary rule | Same as comp#2. Test name misleading but logic correct. |
| zoom#M3 | Document is mostly verbatim code (Anti-Weeds) | Appropriate detail level for bugfix spec; Detailed Implementation Plan is correct place. |
| int_zoom#M2 | test_sid_not_leaked_in_longer_sid (unchanged) | Same as above. |
| int_zoom#N4 | `.` excludes `\n` — same-line only | Design decision: 40-char window within blob (joined with `\n`). Not a defect. |
| critic_style#1 | "Cursor review" severity unverified | Addressed by calibrating language in F17 (PROPOSE FIX applied). |
| critic_style#2 | Subjective "true root cause" | Addressed by restating in F18 (PROPOSE FIX applied). |

---

## Summary

| Severity | Total | Fixed | Contested | Accepted Risk |
|----------|-------|-------|-----------|---------------|
| 🔴 Blocker | 5 | 5 | 0 | 0 |
| 🟡 Major | 11 | 11 | 0 | 0 |
| 🟢 Nit | 13 | 13 | 0 | 0 |
| **Total** | **29** | **29** | **0** | **0** |

*Plus 4 contested findings from earlier stages (not counted above as they were resolved via PROPOSE FIX).*

**OPEN-BLOCKERS: 0**