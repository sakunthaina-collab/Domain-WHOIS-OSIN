# Formal Verification & Fuzzing Findings Log

**Version Baseline:** v1.3 (Court-Grade Baseline)  
**Verification Date:** 2026-11-05T16:34:22+07:00  
**Tooling:** Hypothesis 6.170.14  
**Profiles Executed:** `dev` (200 random examples per property)

This document records the exact invariant violations, counter-examples, and architectural edge cases uncovered during the execution of Patch v1.4 Property-Based Fuzzing.

---

## 1. Findings Matrix

| ID | Module / Component | Invariant Violated | Falsifying Minimal Counter-Example | Root Cause | Severity | Resolution Target |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| **FIND-01** | `core/normalize.py` | Strict ASCII Digit Shape (`^\+?[0-9]+$`) | `raw = '660०'` (`\u0966` Devanagari 0) | `re.compile(r"[^\d+]")` matches Unicode `Nd` category, preserving non-ASCII digits that were not in `_DIGIT_MAP`. | **Medium** | Patch v1.4.1 |
| **FIND-02** | `core/normalize.py` | Embedded Plus Invariant | `raw = '123+456'` | `s.count("+") > 1` ignores single embedded `+` sign if not leading. | **Low** | Patch v1.4.1 |
| **FIND-03** | `core/guardrails.py` | JSONL 1-Record-Per-Line Invariant | `args = {'\x85': None}` (`\x85` Unicode Next Line / NEL) | `json.dumps(..., ensure_ascii=False)` allows raw Unicode line breaks (`\x85`, `\u2028`, `\u2029`), causing line-splitters to break single record into multiple lines. | **High** | Patch v1.4.1 |
| **FIND-04** | `core/guardrails.py` | Tail Truncation in Pure Chain | Deleting `idx = len(lines) - 1` | Pure hash chain verifier `verify_audit_chain()` verifies valid prefixes; tail deletion is only detectable with external anchor (`verify_audit.py`). | **Architectural Insight** | Document & Clarify Test Scope |

---

## 2. Detailed Technical Analysis

### FIND-01: Unicode Digit Leakage in `normalize_phone`
- **Falsifying Example:** `normalize_phone('660०')` -> `'660०'`
- **Analysis:** Python's standard `re` module considers all Unicode numeric digits (`Nd`) as `\d`. When an input contains Devanagari (`०-९`), Thai (`๐-๙`), Bengali, or Gurmukhi digits, `_PHONE_ALLOWED.sub("", s)` preserves them as valid digits. However, downstream systems, SQL queries, and telecom carrier APIs only accept ASCII `[0-9]`.
- **Hotfix Strategy (v1.4.1):** Expand `_DIGIT_MAP` using `unicodedata.digit()` or comprehensive multilingual digit transliteration, and restrict `_PHONE_ALLOWED` to `[^0-9+]` (ASCII-only).

### FIND-02: Embedded Plus Sign Not at Leading Index
- **Falsifying Example:** `normalize_phone('123+456')` -> `'123+456'`
- **Analysis:** `s.count("+") > 1` only cleanses plus signs when there are 2 or more. A single `+` in the middle of a string remains untouched.
- **Hotfix Strategy (v1.4.1):** If `s.startswith("+")`, keep leading `+` and strip all other `+` signs. If not, strip all `+` signs.

### FIND-03: Unicode Line Breaks (`\x85`, `\u2028`, `\u2029`) in JSONL
- **Falsifying Example:** `entries=[('A', {}, {'\x85': None})]`
- **Analysis:** Python's `str.splitlines()` recognizes `\n`, `\r`, `\x85` (Next Line), `\u2028` (Line Separator), and `\u2029` (Paragraph Separator). `json.dumps(..., ensure_ascii=False)` emits raw `\x85` which corrupts JSONL line counting and parsing.
- **Hotfix Strategy (v1.4.1):** Sanitize or escape Unicode control line breaks in `_summarize()` and serialize audit log lines with explicit newline neutralization.

### FIND-04: Tail Truncation Distinction (Pure Chain vs Anchored Chain)
- **Falsifying Example:** In a 2-entry chain, deleting entry 1 (the tail) leaves entry 0 (genesis).
- **Analysis:** A pure hash chain cannot mathematically distinguish between "a chain that stopped at entry 0" and "a chain whose entry 1 was deleted". This formally validates why **Patch v1.2 & v1.3 (External Anchoring & Zero-Entry Trap)** were critical requirements: only an external anchor ledger (`logs/anchor_ledger.json`) or Git tag stores the expected `entry_count` and `head_hash` to catch tail truncation.
- **Test Adjustment (v1.4.1):** 
  - For `verify_audit_chain()` (pure chain), deleting any *internal* entry (where `0 <= delete_idx < len - 1`) must fail.
  - For tail deletion, verify against `verify_audit.py` with anchor ledger to prove truncation trap catches it.
