# core/normalize.py
"""Unicode normalization for inputs (phones, emails, IDs)."""
from __future__ import annotations
import re
import unicodedata

# Arabic-Indic (٠-٩) and Eastern Arabic-Indic (۰-۹) digit mappings
_DIGIT_MAP = str.maketrans(
    "٠١٢٣٤٥٦٧٨٩" "۰۱۲۳۴۵۶۷۸۹",
    "0123456789" "0123456789",
)

_PHONE_ALLOWED = re.compile(r"[^\d+]")


def normalize_phone(raw: str) -> str:
    """+66٨xxx → +668xxx ; drops spaces, hyphens, parentheses."""
    if not raw:
        return ""
    s = unicodedata.normalize("NFKC", raw).strip()
    s = s.translate(_DIGIT_MAP)
    s = _PHONE_ALLOWED.sub("", s)
    if s.count("+") > 1:
        s = "+" + s.replace("+", "")
    return s


def normalize_email(raw: str) -> str:
    return unicodedata.normalize("NFKC", raw).strip().lower()


def normalize_text(raw: str) -> str:
    return unicodedata.normalize("NFKC", raw)


def normalize_args(args: dict) -> dict:
    """Apply per-key normalization based on hint names."""
    out = {}
    for k, v in args.items():
        if isinstance(v, str):
            lk = k.lower()
            if any(t in lk for t in ("phone", "tel", "mobile")):
                out[k] = normalize_phone(v)
            elif "email" in lk:
                out[k] = normalize_email(v)
            else:
                out[k] = normalize_text(v)
        else:
            out[k] = v
    return out
