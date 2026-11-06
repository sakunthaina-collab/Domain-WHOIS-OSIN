# core/normalize.py
"""Unicode normalization for inputs (phones, emails, IDs).

v1.4.1 fixes:
  FIND-01: Devanagari/Thai/Arabic-Indic digits now convert to ASCII
  FIND-02: embedded '+' (e.g. "123+456") now removed
"""
from __future__ import annotations
import re
import unicodedata

# ASCII-only — no Unicode \d
_PHONE_ALLOWED = re.compile(r"[^0-9+]")
_MAX_PHONE_LEN = 20  # hard cap to prevent DoS via long input


def _to_ascii_digit(ch: str) -> str | None:
    """Return ASCII digit for any Unicode decimal digit, else None."""
    try:
        return str(unicodedata.digit(ch))
    except (TypeError, ValueError):
        return None


def normalize_phone(raw: str) -> str:
    """Normalize any phone-like input to ASCII-only form.

    Rules (v1.4.1):
      1. NFKC normalize (folds fullwidth, compatibility)
      2. Convert ALL Unicode decimal digits (Nd) to ASCII 0-9
      3. Strip non [0-9+]
      4. Keep only a single leading '+'
      5. Truncate to _MAX_PHONE_LEN

    Invariants (fuzz-tested):
      • Idempotent:    normalize_phone(normalize_phone(x)) == normalize_phone(x)
      • Shape:         matches ^\\+?[0-9]*$
      • ASCII-only:    no character with ord > 127
    """
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raw = str(raw)

    s = unicodedata.normalize("NFKC", raw).strip()

    # Universal digit → ASCII (FIND-01)
    chars = []
    for ch in s:
        d = _to_ascii_digit(ch)
        chars.append(d if d is not None else ch)
    s = "".join(chars)

    # Strip anything not [0-9+]
    s = _PHONE_ALLOWED.sub("", s)

    # Keep only leading '+' (FIND-02)
    if s.startswith("+"):
        s = "+" + s[1:].replace("+", "")
    else:
        s = s.replace("+", "")

    if len(s) > _MAX_PHONE_LEN:
        s = s[:_MAX_PHONE_LEN]
    return s


def normalize_email(raw: str) -> str:
    if not isinstance(raw, str):
        raw = str(raw) if raw is not None else ""
    return unicodedata.normalize("NFKC", raw).strip().lower()


def normalize_text(raw: str) -> str:
    if not isinstance(raw, str):
        raw = str(raw) if raw is not None else ""
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
