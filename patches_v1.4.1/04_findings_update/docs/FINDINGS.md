# Fuzzing Findings (Hypothesis Round 1)

**Run date:** 2026-11-05  
**Suite:** `tests/properties/` (12 properties, ~2,400 examples)  
**Profile:** dev (200 examples/property)  

## Summary

| ID | Severity | Module | Status (v1.4.1) |
|----|----------|--------|-----------------|
| FIND-01 | Medium | `core/normalize.py` | ✅ RESOLVED |
| FIND-02 | Low | `core/normalize.py` | ✅ RESOLVED |
| FIND-03 | **High** | `core/guardrails.py` | ✅ RESOLVED |
| FIND-04 | Arch. Insight | `core/guardrails.py` | ✅ DOCUMENTED |

**v1.4.1 test result:** all 12 properties pass (re-run with 10× examples).

---

## FIND-01: Unicode Decimal Digits Leak Through Regex

**Discovered by:** `test_normalize_phone_shape_invariant`  
**Minimal counter-example:** `"660\u0966"` (Devanagari 0)

**Root cause:** Python `\d` matches Unicode category Nd (all decimal digits). Regex `[^0-9]` was used, but the loop didn't touch `०`. Result: `"6600"` mixed with Unicode char.

**Fix (v1.4.1):**
- `unicodedata.digit()` universal conversion — covers all Nd scripts
- ASCII-only regex `[^0-9+]`
- Invariant now tested: `all(ord(c) < 128 for c in result)`

**Regression:** `test_find01_unicode_digits_to_ascii`, `test_find01_original_counter_example`

---

## FIND-02: Embedded '+' Not Removed

**Discovered by:** `test_normalize_phone_plus_position_invariant`  
**Minimal counter-example:** `"123+456"`

**Root cause:** old code only removed `+` if count > 1. A single `+` in the middle stayed.

**Fix (v1.4.1):**
- Keep only leading `+`; strip all others
- Invariant: `s.startswith("+") ? s.count("+") == 1 : s.count("+") == 0`

**Regression:** `test_find02_embedded_plus_removed`, `test_find02_original_counter_example`

---

## FIND-03: Unicode Line Separators Break JSONL

**Discovered by:** `test_tamper_any_entry_fails`  
**Minimal counter-example:** `args = {'\u0085': None}`

**Root cause:** `json.dumps(ensure_ascii=False)` writes U+0085 (NEL), U+2028 (LS), U+2029 (PS) as raw bytes. These ARE line separators per Unicode and per Python `str.splitlines()`. An auditor reading with `splitlines()` would see 2 "lines" for 1 record.

**Why this is HIGH severity:** even though the chain itself is technically intact, an auditor who uses `splitlines()` (which is the natural approach — e.g., `wc -l` counts them as newlines) would see corrupted output and might incorrectly conclude the log was tampered. Reputational damage / case invalidation risk.

**Fix (v1.4.1):**
- `_safe_json_line()` escapes these three chars to `\uXXXX` before writing
- Hash computation unchanged (was always using `ensure_ascii=True`)
- `json.loads` still recovers the original characters on read

**Regression:** `test_find03_line_separator_in_value` (3 chars × 2 tests), `test_find03_original_counter_example`, `test_find03_original_data_roundtrips`

---

## FIND-04: Pure Chain Cannot Detect Tail Deletion (by design)

**Discovered by:** `test_delete_any_entry_fails` (test contract violation)  
**Behavior observed:** deleting the last entry of `audit.jsonl` still passes `verify_audit_chain()`.

**Root cause:** This is not a bug — it's a mathematical property of hash chains. A prefix of a valid chain is still a valid chain. Without external knowledge of "how many entries there should be," tail deletion is indistinguishable from "the chain was always this long."

**Why this matters for the audit trail:**
This finding is **positive evidence** that v1.2's external anchor is architecturally necessary, not defensive paranoia. A pure-chain-only system *cannot* detect:
- Tail truncation
- Wholesale file deletion
- Rollback to an older version

Only an external anchor (which records expected count + head hash) can detect these.

**Fix (v1.4.1):**
- **Code:** none. `verify_audit_chain` behavior is correct.
- **Test:** rename and split into:
  - `test_find04_pure_chain_cannot_detect_tail_deletion` — asserts the limitation is documented
  - `test_find04_internal_deletion_still_detected` — asserts internal deletion IS caught
- **Docs:** added to `AUDITOR_GUIDE.md` §4.3 (Residual Risk) — "tail deletion requires anchor"

**Regressions:** both tests above

---

## Fuzzing profile used

```python
# tests/conftest.py
from hypothesis import settings, HealthCheck

settings.register_profile(
    "dev",
    max_examples=200,
    deadline=None,
)
settings.register_profile(
    "ci",
    max_examples=2000,
    deadline=None,
)
settings.register_profile(
    "nightly",
    max_examples=10000,
    deadline=None,
)
```

## How to reproduce any finding

```bash
# Reproduce a specific falsifying example
pytest tests/properties/test_normalize_properties.py \
       --hypothesis-seed=<seed-from-failure> -v

# Full re-run with CI profile (2000 examples per property)
HYPOTHESIS_PROFILE=ci pytest tests/properties/ -v

# Nightly (10k examples)
HYPOTHESIS_PROFILE=nightly pytest tests/properties/ -v
```

## Sign-off
Fixed by: Patch v1.4.1  
Verified by: `pytest agent/tests/test_fuzz_regressions.py agent/tests/properties/ -v`  
