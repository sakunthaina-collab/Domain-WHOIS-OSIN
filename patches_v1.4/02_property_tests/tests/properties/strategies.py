# tests/properties/strategies.py
"""Shared Hypothesis strategies for property-based fuzzing."""
from __future__ import annotations
import string
from hypothesis import strategies as st

# ASCII & Unicode digit characters
ASCII_DIGITS = string.digits
ARABIC_INDIC_DIGITS = "٠١٢٣٤٥٦٧٨٩"
EAST_ARABIC_INDIC_DIGITS = "۰۱۲۳۴۵۶۷۸۹"
DEVANAGARI_DIGITS = "०१२३४५६७८९"
THAI_DIGITS = "๐๑๒๓๔๕๖๗๘๙"

# Phone number strategies
st_phone_digits = st.text(
    alphabet=st.sampled_from(
        list(ASCII_DIGITS)
        + list(ARABIC_INDIC_DIGITS)
        + list(EAST_ARABIC_INDIC_DIGITS)
        + list(DEVANAGARI_DIGITS)
        + list(THAI_DIGITS)
    ),
    min_size=1,
    max_size=20,
)

st_separators = st.sampled_from(["", " ", "-", ".", "(", ")", "/", " "])

@st.composite
def strategy_raw_phone(draw) -> str:
    """Generate realistic or semi-structured phone numbers with random delimiters and formats."""
    has_plus = draw(st.booleans())
    prefix = "+" if has_plus else ""
    country_code = draw(st.sampled_from(["66", "886", "1", "44", "81", "86", "65", "60"]))
    parts = [
        prefix + country_code,
        draw(st_phone_digits),
        draw(st_phone_digits),
    ]
    sep = draw(st_separators)
    return sep.join(parts)

# Chaotic raw string strategy (arbitrary Unicode, control chars, random + signs)
st_chaotic_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),  # exclude surrogate pairs for valid unicode
    ),
    max_size=100,
)

# Audit log strategies
st_action_name = st.text(alphabet=string.ascii_letters + "_-", min_size=1, max_size=32)
st_case_id = st.text(alphabet=string.ascii_letters + string.digits + "-_", min_size=1, max_size=32)
st_json_scalar = st.one_of(st.text(max_size=30), st.integers(), st.floats(allow_nan=False), st.booleans(), st.none())
st_args_dict = st.dictionaries(
    keys=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=10),
    values=st_json_scalar,
    max_size=5,
)

@st.composite
def strategy_audit_entries(draw, min_entries=1, max_entries=15):
    """Generate a sequence of audit action tuples (action, args, result)."""
    n = draw(st.integers(min_value=min_entries, max_value=max_entries))
    entries = []
    for _ in range(n):
        action = draw(st_action_name)
        args = draw(st_args_dict)
        res = draw(st.dictionaries(keys=st.text(min_size=1, max_size=10), values=st_json_scalar, max_size=3))
        entries.append((action, args, res))
    return entries
