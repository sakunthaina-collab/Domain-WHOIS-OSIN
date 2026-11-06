# core/case_id.py
"""Case ID validator — single source of truth for format rules."""
import re

# Format: YYYY-MM-DD-CASE-XXX
# - YYYY-MM-DD  = date
# - CASE-       = literal prefix
# - XXX         = alphanumeric + hyphen, 1-60 chars
_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}-CASE-[A-Z0-9][A-Z0-9-]{0,60}$")
_MAX_LEN = 80
_FORBIDDEN = ("\x00", "/", "\\", "..", ":", "*", "?", '"', "<", ">", "|")


def validate_case_id(case_id: str) -> str:
    """Validate case_id format. Raise ValueError on invalid.

    Rules:
      - Must be str, non-empty, <= 80 chars
      - No path separators or NUL bytes (prevents traversal)
      - Must match YYYY-MM-DD-CASE-XXX pattern
    """
    if not isinstance(case_id, str):
        raise ValueError(f"case_id must be str, got {type(case_id).__name__}")
    if not case_id:
        raise ValueError("case_id is empty")
    if len(case_id) > _MAX_LEN:
        raise ValueError(f"case_id too long ({len(case_id)} > {_MAX_LEN})")
    for bad in _FORBIDDEN:
        if bad in case_id:
            raise ValueError(
                f"case_id contains forbidden sequence {bad!r}: {case_id!r}")
    if not _PATTERN.match(case_id):
        raise ValueError(
            f"case_id does not match YYYY-MM-DD-CASE-XXX pattern: {case_id!r}")
    return case_id


def is_valid_case_id(case_id: str) -> bool:
    """Non-raising check."""
    try:
        validate_case_id(case_id)
        return True
    except ValueError:
        return False
