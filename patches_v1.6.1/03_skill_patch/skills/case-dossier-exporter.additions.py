# ═══════════════════════════════════════════════════════════════
# ADD AT TOP OF FILE
# ═══════════════════════════════════════════════════════════════
from core.case_id import validate_case_id


# ═══════════════════════════════════════════════════════════════
# ADD AS FIRST LINE INSIDE def run(...)
# ═══════════════════════════════════════════════════════════════
def run(case_id: str, lang=None, **kwargs):
    # ▼ NEW: validate case_id (defense in depth)
    case_id = validate_case_id(case_id)

    # ... (rest of function unchanged)
