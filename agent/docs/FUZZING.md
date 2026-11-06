# Property-Based Fuzzing & Formal Verification Guide

**Standard Compliance:** ISO/IEC 27037:2012 & ISO/IEC 27041:2015 (Assuring Digital Evidence Tool Integrity)  
**Testing Framework:** [Hypothesis](https://hypothesis.readthedocs.io/)  
**Profiles Available:**
- `dev` (default): 200 random examples per property
- `ci`: 1,000 random examples per property
- `debug`: 50 examples with verbose logging

---

## 1. What We Fuzz & Why

In digital forensics and legal reporting, hardcoded unit tests only prove the absence of errors on anticipated paths. Property-based testing mathematically generates thousands of edge cases, chaotic inputs, and adversarial data to verify that foundational **invariants** hold under all circumstances.

### Modules Covered

| Module | Properties Tested | Key Invariants Verified |
| :--- | :--- | :--- |
| **`core/normalize.py`** | 5 properties | • Idempotency: `f(f(x)) == f(x)`<br>• Shape: Output is strictly ASCII digits (`^\+?[0-9]+$`) or empty<br>• Script invariance (Arabic-Indic, Eastern Arabic-Indic, Devanagari, Thai)<br>• Max one `+` sign and strictly at position 0 |
| **`core/guardrails.py`** | 4 properties | • Validity: All sequential entries pass verification<br>• Tamper detection: Any field alteration fails hash chain<br>• Deletion detection: Removing any entry breaks `prev_hash`<br>• Reordering detection: Swapping entries breaks chain |
| **`core/artifact_manifest.py`** | 3 properties | • Determinism: Same directory state produces identical Merkle root<br>• Avalanche effect: Single-byte mutation breaks Merkle root<br>• Empty directory state is mathematically well-defined |

---

## 2. How to Run Fuzzing Locally

```powershell
# From the project root or agent/ directory:
pip install hypothesis

# Run with standard dev profile (200 examples per property)
pytest agent/tests/properties -v

# Run with CI profile (1,000 examples per property)
$env:HYPOTHESIS_PROFILE = "ci"
pytest agent/tests/properties -v --hypothesis-show-statistics

# Run specific property test suite
pytest agent/tests/properties/test_normalize_properties.py -v
```

---

## 3. How to Reproduce a Failed Falsifying Example

When Hypothesis discovers a counter-example that falsifies an invariant, it displays a minimal failing reproduction snippet in the console:

```python
Falsifying example: test_normalize_phone_plus_position_invariant(
    raw='123+456',
)
```

To reproduce the exact failure in isolation:
1. Copy the failing input to a standard unit test.
2. Or use the `@reproduce_failure(...)` decorator provided by Hypothesis output.
3. Fix the underlying invariant in the implementation.
