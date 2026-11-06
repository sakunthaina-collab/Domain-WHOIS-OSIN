# tests/properties/test_normalize_properties.py
"""Property-based tests for core/normalize.py."""
from __future__ import annotations
import re
from hypothesis import given, settings
from hypothesis import strategies as st

from core.normalize import normalize_phone, normalize_email, normalize_text
from tests.properties.strategies import (
    strategy_raw_phone,
    st_chaotic_text,
)

# ---------------------------------------------------------------------------
# Property 1: Idempotency
# normalize_phone(normalize_phone(x)) == normalize_phone(x)
# ---------------------------------------------------------------------------
@given(raw=st.one_of(strategy_raw_phone(), st_chaotic_text))
def test_normalize_phone_idempotent(raw: str):
    first = normalize_phone(raw)
    second = normalize_phone(first)
    assert first == second, f"Idempotence failed: {first!r} != {second!r} from raw={raw!r}"


# ---------------------------------------------------------------------------
# Property 2: Script / Separator Invariance
# Replacing separators with spaces/dashes/parentheses produces identical normalized phone
# ---------------------------------------------------------------------------
@given(digits=st.text(alphabet="0123456789", min_size=6, max_size=15), has_plus=st.booleans())
def test_normalize_phone_separator_invariant(digits: str, has_plus: bool):
    prefix = "+" if has_plus else ""
    raw1 = f"{prefix}{digits}"
    # Insert random spaces, hyphens, and dots
    mid = len(digits) // 2
    raw2 = f"{prefix}{digits[:mid]} - ({digits[mid:]})"
    raw3 = f" {prefix} {digits[:mid]}.{digits[mid:]} "
    
    res1 = normalize_phone(raw1)
    res2 = normalize_phone(raw2)
    res3 = normalize_phone(raw3)
    assert res1 == res2 == res3, f"Separator invariant violated: {res1!r}, {res2!r}, {res3!r}"


# ---------------------------------------------------------------------------
# Property 3: Output Shape Invariant
# Output must be either empty string or match ^\+?[0-9]*$ (strict ASCII digits)
# ---------------------------------------------------------------------------
_VALID_PHONE_SHAPE = re.compile(r"^\+?[0-9]*$")

@given(raw=st.one_of(strategy_raw_phone(), st_chaotic_text))
def test_normalize_phone_shape_invariant(raw: str):
    res = normalize_phone(raw)
    assert _VALID_PHONE_SHAPE.fullmatch(res) is not None, (
        f"Phone shape invariant violated: {res!r} from raw={raw!r} (must be ^\\+?[0-9]*$)"
    )


# ---------------------------------------------------------------------------
# Property 4: Plus Sign Invariant
# At most one '+', and if present, must strictly be the first character
# ---------------------------------------------------------------------------
@given(raw=st.one_of(strategy_raw_phone(), st_chaotic_text))
def test_normalize_phone_plus_position_invariant(raw: str):
    res = normalize_phone(raw)
    count_plus = res.count("+")
    assert count_plus <= 1, f"Multiple '+' signs found in normalized: {res!r}"
    if count_plus == 1:
        assert res.startswith("+"), f"'+' sign must be leading character: {res!r}"


# ---------------------------------------------------------------------------
# Property 5: Email Idempotency & Lowercase Invariant
# -----------------------------------------------------------
@given(raw=st_chaotic_text)
def test_normalize_email_properties(raw: str):
    res = normalize_email(raw)
    # Idempotent
    assert normalize_email(res) == res
    # Always lowercased
    assert res == res.lower()
